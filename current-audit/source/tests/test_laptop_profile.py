import pytest

from devfleet.resource_profiles import LAPTOP_PROFILE_DEFAULT, laptop_surrogate_profile


def test_laptop_default_is_conservative_5g_2g():
    assert laptop_surrogate_profile() == LAPTOP_PROFILE_DEFAULT


def test_laptop_lower_bound_fails_closed():
    with pytest.raises(ValueError, match="below"):
        laptop_surrogate_profile(failover_memory_gb=3)
    with pytest.raises(ValueError, match="below"):
        laptop_surrogate_profile(vault_memory_gb=1)
