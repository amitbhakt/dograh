"""Phone number synchronization service for telephony providers."""

from typing import Any

from loguru import logger

from api.db import db_client
from api.db.telephony_phone_number_client import TelephonyPhoneNumberConflictError
from api.schemas.telephony_phone_number import ProviderSyncStatus
from api.services.telephony.factory import get_telephony_provider_by_id
from api.services.telephony.inbound_routing import (
    InboundRoutingConflictError,
    assert_no_inbound_routing_conflict,
)
from api.utils.telephony_address import normalize_telephony_address


async def sync_available_phone_numbers_for_config(
    config_id: int, organization_id: int
) -> ProviderSyncStatus:
    """Import provider-owned outbound/inbound numbers into Dograh if the provider exposes them."""
    try:
        provider = await get_telephony_provider_by_id(config_id, organization_id)
    except Exception as e:
        logger.error(f"Failed to load telephony provider for config {config_id}: {e}")
        return ProviderSyncStatus(ok=False, message=f"Provider load failed: {e}")

    discover_records = getattr(provider, "get_available_phone_number_records", None)
    records: list[dict[str, Any]] = []

    if callable(discover_records):
        try:
            records = await discover_records()
        except Exception as e:
            logger.error(
                f"Failed to discover phone number records for config {config_id}: {e}"
            )
            return ProviderSyncStatus(ok=False, message=f"Provider sync failed: {e}")
    else:
        discover_numbers = getattr(provider, "get_available_phone_numbers", None)
        if not callable(discover_numbers):
            return ProviderSyncStatus(
                ok=True,
                message="Provider does not expose discoverable outbound numbers.",
            )

        try:
            available_numbers = await discover_numbers()
            records = [{"address": num} for num in (available_numbers or [])]
        except Exception as e:
            logger.error(
                f"Failed to discover phone numbers for config {config_id}: {e}"
            )
            return ProviderSyncStatus(ok=False, message=f"Provider sync failed: {e}")

    existing_rows = await db_client.list_phone_numbers_for_config(config_id)
    existing_map = {
        row.address_normalized: row for row in existing_rows if row.address_normalized
    }
    has_default_caller = any(row.is_default_caller_id for row in existing_rows)
    imported = 0
    skipped = 0
    deactivated = 0

    config_row = await db_client.get_telephony_configuration(config_id)
    provider_name = config_row.provider if config_row else None
    provider_credentials = config_row.credentials if config_row else None

    for item in records:
        address = item.get("address")
        if not address:
            continue
        try:
            normalized = normalize_telephony_address(address).canonical
        except ValueError:
            skipped += 1
            logger.warning(
                f"Skipping unparseable phone number discovered for config {config_id}: "
                f"{address!r}"
            )
            continue

        extra_metadata = item.get("extra_metadata") or {}

        if normalized in existing_map:
            existing_row = existing_map[normalized]
            if existing_row and extra_metadata:
                merged = {**(existing_row.extra_metadata or {}), **extra_metadata}
                if merged != existing_row.extra_metadata:
                    await db_client.update_phone_number(
                        phone_number_id=existing_row.id,
                        telephony_configuration_id=config_id,
                        extra_metadata=merged,
                    )
            continue

        try:
            if provider_name:
                await assert_no_inbound_routing_conflict(
                    provider=provider_name,
                    credentials=provider_credentials,
                    addresses=[normalized],
                    organization_id=organization_id,
                )
            await db_client.create_phone_number(
                organization_id=organization_id,
                telephony_configuration_id=config_id,
                address=address,
                is_active=True,
                is_default_caller_id=not has_default_caller and imported == 0,
                extra_metadata=extra_metadata,
            )
            imported += 1
            existing_map[normalized] = None
            if not has_default_caller:
                has_default_caller = True
        except TelephonyPhoneNumberConflictError:
            skipped += 1
            logger.info(
                f"Skipping already-existing phone number {address!r} while syncing "
                f"config {config_id}"
            )
        except InboundRoutingConflictError:
            skipped += 1
            logger.warning(
                f"Skipping conflicting phone number {address!r} while syncing config {config_id}: "
                "already registered on another inbound route"
            )

    # Issue 1: deactivate rows that are no longer present in the provider result.
    discovered = {
        normalize_telephony_address(item["address"]).canonical
        for item in records
        if item.get("address")
    }
    for row in existing_rows:
        if row.is_active and row.address_normalized and row.address_normalized not in discovered:
            await db_client.update_phone_number(
                phone_number_id=row.id,
                telephony_configuration_id=config_id,
                is_active=False,
            )
            deactivated += 1
            logger.info(
                f"Deactivated stale phone number {row.address_normalized!r} for config {config_id}: "
                "no longer present in provider result"
            )

    if imported or deactivated:
        parts = []
        if imported:
            parts.append(f"Imported {imported} phone number(s).")
        if deactivated:
            parts.append(f"Deactivated {deactivated} stale phone number(s).")
        message = " ".join(parts)
        if skipped:
            message += f" Skipped {skipped} duplicate or invalid number(s)."
        return ProviderSyncStatus(ok=True, message=message)

    if not records:
        return ProviderSyncStatus(
            ok=True,
            message="No discoverable phone numbers were returned by the provider.",
        )

    return ProviderSyncStatus(
        ok=True,
        message=f"No new phone numbers to import ({skipped} duplicate or invalid number(s) skipped)."
        if skipped
        else "No new phone numbers to import.",
    )
