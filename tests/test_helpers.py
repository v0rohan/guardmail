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

    def test_does_not_flag_real_banks_without_bank_in_domain(self):
        # "bank" used to be treated as a brand, flagging chase.com, bofa.com etc.
        assert index.detect_spoofing("Chase Bank <no-reply@alerts.chase.com>") is False
        assert index.detect_spoofing("Bank of America <alerts@bofa.com>") is False

    def test_does_not_flag_brand_substring_in_display_name(self):
        # "meta" inside "Metadata" is not a brand claim
        assert index.detect_spoofing("Metadata Weekly <digest@metadataweekly.io>") is False

    def test_flags_brand_buried_in_lookalike_domain(self):
        assert index.detect_spoofing("Account Team <info@paypal.account-check.net>") is True

    def test_flags_lookalike_hyphenated_domain(self):
        assert index.detect_spoofing("Netflix <billing@netflix-payments.co>") is True


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
    def test_flags_dangerous_keyword_domain(self):
        links = index.parse_and_sandbox_links("Click here: https://verify-now.tk/login")
        assert len(links) == 1
        assert "Dangerous" in links[0]["safety_status"]

    def test_clears_benign_url(self):
        links = index.parse_and_sandbox_links("See https://example.com/about for details")
        assert len(links) == 1
        assert "Dangerous" not in links[0]["safety_status"]

    def test_no_urls_returns_empty_list(self):
        assert index.parse_and_sandbox_links("No links in this email at all.") == []

    def test_strips_trailing_punctuation(self):
        links = index.parse_and_sandbox_links("Visit https://example.com/page.")
        assert links[0]["url"] == "https://example.com/page"

    def test_trusted_domain_login_page_is_not_dangerous(self):
        # Real providers' own sign-in/verify pages used to false-positive
        for url in ("https://accounts.google.com/signin", "https://www.paypal.com/myaccount/login"):
            assert index.classify_link(url) == "Trusted domain"

    def test_login_subdomain_of_unknown_but_normal_domain_is_not_dangerous(self):
        assert "Dangerous" not in index.classify_link("https://login.salesforce.com/home")

    def test_single_login_path_on_unknown_domain_is_not_dangerous(self):
        assert "Dangerous" not in index.classify_link("https://www.smallbusiness.com/login")

    def test_flags_secure_as_a_whole_word_in_registered_domain(self):
        assert "Dangerous" in index.classify_link("http://paypal-secure-verify.com")

    def test_flags_brand_in_lookalike_host(self):
        assert "Dangerous" in index.classify_link("https://paypal.account-check.net/home")

    def test_flags_raw_ip_link(self):
        assert "Dangerous" in index.classify_link("http://203.0.113.7/download")

    def test_flags_credentials_in_url_authority(self):
        assert "Dangerous" in index.classify_link("https://paypal.com@evil.example.net/signin")

    def test_shortener_is_cautioned_but_not_dangerous(self):
        status = index.classify_link("https://bit.ly/3xZ9qLm")
        assert "Shortened" in status
        assert "Dangerous" not in status


class TestFallbackCategorize:
    def test_detects_scam_with_money_and_urgency(self):
        assert index.fallback_categorize("Please verify your bank login") == "Scam Alert"

    def test_detects_spam_with_two_promo_keywords(self):
        assert index.fallback_categorize("Huge discount sale this weekend") == "Spam"

    def test_scam_takes_priority_over_spam(self):
        assert index.fallback_categorize("Free discount, please verify your bank account") == "Scam Alert"

    def test_does_not_flag_legitimate_verify_or_login_language(self):
        assert index.fallback_categorize(
            "Action Required: Please verify your student account information before "
            "the registration deadline. Log in to BuckeyeLink to confirm your details."
        ) == "Important"

    def test_neutral_body_is_important(self):
        assert index.fallback_categorize("Let's meet for lunch tomorrow") == "Important"

    def test_money_keyword_alone_is_not_a_scam(self):
        # A PayPal receipt mentions money terms but has no urgency hook
        assert index.fallback_categorize(
            "You sent a payment of $12.99 USD to Spotify AB. Thanks for using PayPal."
        ) == "Important"

    def test_urgency_alone_is_not_a_scam(self):
        assert index.fallback_categorize(
            "Reminder: your library books are due immediately after the holiday."
        ) == "Important"

    def test_single_promo_keyword_is_not_spam(self):
        assert index.fallback_categorize("Feel free to stop by whenever works.") == "Important"


class TestBuildRiskFactors:
    def test_factors_sum_matches_risk_index_up_to_the_cap(self):
        links = [{"safety_status": "Dangerous / Suspicious address"}] * 2
        factors = index.build_risk_factors("Scam Alert", True, links)
        assert min(sum(f["points"] for f in factors), 100) == index.calculate_risk_index("Scam Alert", True, links)

    def test_clean_email_has_only_baseline(self):
        factors = index.build_risk_factors("Important", False, [])
        assert len(factors) == 1
        assert factors[0]["points"] == 10
