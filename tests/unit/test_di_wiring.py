from datetime import datetime

from verion.platform.di import get_clock, get_id_generator


def test_clock_resolves_to_a_working_adapter():
    clock = get_clock()

    assert isinstance(clock.now(), datetime)


def test_id_generator_resolves_to_a_working_adapter():
    id_generator = get_id_generator()

    assert id_generator.new_id() != id_generator.new_id()


def test_providers_are_cached_singletons():
    assert get_clock() is get_clock()
    assert get_id_generator() is get_id_generator()
