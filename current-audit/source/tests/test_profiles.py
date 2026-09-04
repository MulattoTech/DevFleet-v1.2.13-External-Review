from devfleet.profiles import get_profile
def test_profiles():
 assert get_profile('strict').block_hardening;assert get_profile('balanced').allow_tailnet;assert get_profile('fast').allow_devices
