from datetime import datetime

from rule_engine import rule_based_check


def test_after_hours_access_flagged(db, sample_user, activity_factory, rule_config):
    activity = activity_factory(
        sample_user, activity_type="login", timestamp=datetime(2026, 1, 5, 23, 0)
    )
    flags = rule_based_check(activity, sample_user, rule_config)
    assert "After-hours access" in flags


def test_business_hours_access_not_flagged(db, sample_user, activity_factory, rule_config):
    activity = activity_factory(
        sample_user, activity_type="login", timestamp=datetime(2026, 1, 5, 10, 0)
    )
    flags = rule_based_check(activity, sample_user, rule_config)
    assert "After-hours access" not in flags


def test_excessive_download_flagged(db, sample_user, activity_factory, rule_config):
    activity = activity_factory(
        sample_user,
        activity_type="download",
        data_volume_mb=750,
        timestamp=datetime(2026, 1, 5, 10, 0),
    )
    flags = rule_based_check(activity, sample_user, rule_config)
    assert "Excessive data download" in flags


def test_unauthorized_resource_access_flagged(db, sample_user, activity_factory, rule_config):
    # sample_user role is "Analyst"; payroll_db is restricted to HR/Finance in rule_config fixture
    sample_user.role = "Software Engineer"
    activity = activity_factory(
        sample_user,
        activity_type="file_access",
        resource_accessed="payroll_db",
        timestamp=datetime(2026, 1, 5, 10, 0),
    )
    flags = rule_based_check(activity, sample_user, rule_config)
    assert "Unauthorized resource access" in flags


def test_authorized_resource_access_not_flagged(db, sample_user, activity_factory, rule_config):
    # sample_user role "Analyst" IS authorized for payroll_db per rule_config fixture ("Finance"/"HR")
    sample_user.department = "Finance"
    activity = activity_factory(
        sample_user,
        activity_type="file_access",
        resource_accessed="payroll_db",
        timestamp=datetime(2026, 1, 5, 10, 0),
    )
    # role list is ["HR", "Finance"]; set role to Finance-authorized value
    sample_user.role = "Finance"
    flags = rule_based_check(activity, sample_user, rule_config)
    assert "Unauthorized resource access" not in flags


def test_multiple_flags_can_coexist(db, sample_user, activity_factory, rule_config):
    sample_user.role = "Software Engineer"
    activity = activity_factory(
        sample_user,
        activity_type="download",
        resource_accessed="payroll_db",
        data_volume_mb=1000,
        timestamp=datetime(2026, 1, 5, 2, 0),
    )
    flags = rule_based_check(activity, sample_user, rule_config)
    assert set(flags) == {
        "After-hours access",
        "Excessive data download",
        "Unauthorized resource access",
    }
