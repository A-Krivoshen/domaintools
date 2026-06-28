import unittest

import app as app_module


class MobileUxTests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.client = self.app.test_client()

    def test_viewport_fit_cover_for_ios_safe_areas(self):
        html = self.client.get("/?lang=ru").get_data(as_text=True)
        self.assertIn("viewport-fit=cover", html)

    def test_scroll_to_top_markup_and_mobile_hide_css(self):
        html = self.client.get("/?lang=ru").get_data(as_text=True)
        css = self._read_app_css()
        self.assertIn('id="scrollToTop"', html)
        self.assertIn(".scroll-to-top--disabled-mobile", css)
        self.assertIn("display: none !important", css)

    def test_mobile_bottom_nav_touch_layout_css(self):
        css = self._read_app_css()
        self.assertIn("mobile-bottom-nav", css)
        self.assertIn("safe-area-inset-bottom", css)
        self.assertIn("(pointer: coarse)", css)

    def test_ios_form_input_font_size_guard(self):
        css = self._read_app_css()
        self.assertIn("font-size: 16px", css)

    def test_key_pages_have_mobile_nav(self):
        for path in ("/", "/hosting", "/whois", "/dns", "/domains"):
            with self.subTest(path=path):
                html = self.client.get(f"{path}?lang=ru").get_data(as_text=True)
                self.assertIn("mobile-bottom-nav", html)

    def test_mobile_nav_uses_full_ru_labels_not_abbreviations(self):
        html = self.client.get("/?lang=ru").get_data(as_text=True)
        self.assertIn('nav-label--long">Куда ведёт', html)
        self.assertIn('nav-label--long">Кто владелец', html)
        self.assertIn('nav-label--long">Полная проверка', html)
        self.assertIn('nav-label--long">Проверка сайта', html)
        self.assertIn('nav-label--long">Проверить безопасность', html)

    def test_mobile_nav_uses_full_en_labels_not_abbreviations(self):
        html = self.client.get("/?lang=en").get_data(as_text=True)
        self.assertIn('nav-label--long">Where It Points', html)
        self.assertIn('nav-label--long">Who Owns It', html)
        self.assertIn('nav-label--long">Full Check', html)
        self.assertIn('nav-label--long">Site Checker', html)
        self.assertIn('nav-label--long">Check Security', html)

    def test_mobile_nav_group_labels_are_not_forced_uppercase(self):
        css = self._read_app_css()
        self.assertNotRegex(css, r"\.nav-group-label\s*\{[^}]*text-transform:\s*uppercase")

    def _read_app_css(self) -> str:
        css_path = app_module.os.path.join(app_module.app.root_path, "static", "app.css")
        with open(css_path, "r", encoding="utf-8") as fh:
            return fh.read()


if __name__ == "__main__":
    unittest.main()