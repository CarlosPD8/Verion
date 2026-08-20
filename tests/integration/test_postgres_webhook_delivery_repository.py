from verion.modules.scanning.adapters.outbound.db.repository import (
    PostgresWebhookDeliveryRepository,
)


async def test_first_call_for_a_delivery_id_returns_true(db_session):
    repository = PostgresWebhookDeliveryRepository(db_session)

    assert await repository.record_if_new("delivery-1") is True


async def test_a_repeated_delivery_id_returns_false(db_session):
    repository = PostgresWebhookDeliveryRepository(db_session)
    await repository.record_if_new("delivery-1")

    assert await repository.record_if_new("delivery-1") is False


async def test_different_delivery_ids_are_independently_new(db_session):
    repository = PostgresWebhookDeliveryRepository(db_session)

    assert await repository.record_if_new("delivery-1") is True
    assert await repository.record_if_new("delivery-2") is True
