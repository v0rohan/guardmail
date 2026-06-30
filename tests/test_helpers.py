import index


class TestDetectSpoofing:
    def test_flags_brand_in_display_name_with_mismatched_domain(self):
        assert index.detect_spoofing("PayPal Support <support@totally-fake-site.tk>") is True

    def test_does_not_flag_brand_matching_its_own_domain(self):
        assert index.detect_spoofing("PayPal <service@paypal.com>") is False

    def test_does_not_flag_unrelated_sender(self):
        assert index.detect_spoofing("John Doe <john@example.com>") is False

    def test_flags_brand_in_local_part_without_angle_brackets(self):
        assert index.detect_spoofing("paypal-support@evil-domain.tk") is True

    def test_does_not_flag_legitimate_security_alert_senders(self):
        assert index.detect_spoofing("Google Security <no-reply@accounts.google.com>") is False
        assert index.detect_spoofing("Apple Security <security@apple.com>") is False


class TestCalculateRiskIndex:
    def test_scam_alert_base_score(self):
        assert index.calculate_risk_index("Scam Alert", False, []) == 55

    def test_spam_with_spoofing_and_dangerous_link(self):
        links = [{"safety_status": "Dangerous / Blacklisted Match"}]
        assert index.calculate_risk_index("Spam", True, links) == 70

    def test_important_with_no_risk_factors(self):
        assert index.calculate_risk_index("Important", False, []) == 10

    def test_score_caps_at_100(self):
        links = [{"safety_status": "Dangerous / Blacklisted Match"}] * 5
        assert index.calculate_risk_index("Scam Alert", True, links) == 100


class TestParseAndSandboxLinks:
    def test_flags_dangerous_keyword_url(self):
        links = index.parse_and_sandbox_links("Click here: https://verify-now.tk/login")
        assert len(links) == 1
        assert links[0]["safety_status"] == "Dangerous / Blacklisted Match"

    def test_clears_benign_url(self):
        links = index.parse_and_sandbox_links("See https://example.com/about for details")
        assert len(links) == 1
        assert links[0]["safety_status"] == "External Link / Unverified Clear"

    def test_no_urls_returns_empty_list(self):
        assert index.parse_and_sandbox_links("No links in this email at all.") == []

    def test_strips_trailing_punctuation(self):
        links = index.parse_and_sandbox_links("Visit https://example.com/page.")
        assert links[0]["url"] == "https://example.com/page"

    def test_does_not_flag_security_as_substring_of_secure(self):
        links = index.parse_and_sandbox_links("Review at https://myaccount.google.com/security")
        assert links[0]["safety_status"] == "External Link / Unverified Clear"

    def test_still_flags_secure_as_a_whole_word(self):
        links = index.parse_and_sandbox_links("Confirm at http://paypal-secure-verify.com")
        assert links[0]["safety_status"] == "Dangerous / Blacklisted Match"


class TestFallbackCategorize:
    def test_detects_scam_keyword(self):
        assert index.fallback_categorize("Please verify your bank login") == "Scam Alert"

    def test_detects_spam_keyword(self):
        assert index.fallback_categorize("Huge discount sale this weekend") == "Spam"

    def test_scam_takes_priority_over_spam(self):
        assert index.fallback_categorize("Free discount, please verify your bank account") == "Scam Alert"

    def test_neutral_body_is_important(self):
        assert index.fallback_categorize("Let's meet for lunch tomorrow") == "Important"
