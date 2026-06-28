import unittest

import app as app_module


class RegistrarOffersTests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.client = self.app.test_client()
        self.ctx = self.app.app_context()
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    def test_registrar_offers_returns_featured_providers(self):
        offers = app_module._registrar_offers(featured_only=True)
        ids = [o["id"] for o in offers]
        self.assertEqual(ids, ["beget", "regru", "sweb"])
        self.assertIn("beget.com", app_module._registrar_buy_url("beget", "example.com"))
        self.assertIn("reg.ru", app_module._registrar_buy_url("regru", "example.ru"))
        self.assertIn("sweb.ru", app_module._registrar_buy_url("sweb", "example.ru"))

    def test_registrar_buy_urls_prefill_domain_for_regru_and_sweb(self):
        regru = app_module._registrar_buy_url("regru", "twc.tatar")
        sweb = app_module._registrar_buy_url("sweb", "twc.tatar")
        self.assertIn("domain/new?domain=twc.tatar", regru)
        self.assertIn("rlink=reflink-11522689", regru)
        self.assertNotIn("/domain/new/twc.tatar", regru)
        self.assertIn("sweb.ru/domains/?d=twc.tatar", sweb)
        self.assertIn("utm_term=siehpehi", sweb)
        self.assertNotIn("/registration/", sweb)

    def test_affiliate_buy_url_uses_default_registrar(self):
        with self.app.test_request_context("/"):
            url = app_module._affiliate_buy_url("example.com")
        self.assertIn("beget.com", url)
        self.assertIn("example.com", url)

    def test_registrars_page_renders_providers(self):
        resp = self.client.get("/registrars?lang=ru")
        self.assertEqual(200, resp.status_code)
        html = resp.get_data(as_text=True)
        self.assertIn("REG.RU", html)
        self.assertIn("SpaceWeb", html)
        self.assertIn("data-ref-track", html)
        self.assertIn("regru-verification", html)

    def test_registrar_buy_buttons_partial_renders_three_providers(self):
        tpl = self.app.jinja_env.get_template("_registrar_buy_buttons.html")
        html = tpl.render(
            domain="example.ru",
            placement="test",
            registrar_offers_featured=app_module._registrar_offers,
            registrar_buy_url=app_module._registrar_buy_url,
            get_locale=lambda: "ru",
            tr=lambda ru, en: ru,
        )
        self.assertIn("Beget", html)
        self.assertIn("REG.RU", html)
        self.assertIn("SpaceWeb", html)
        self.assertEqual(html.count("data-buy-registrar="), 3)

    def test_sitemap_includes_registrars(self):
        xml = self.client.get("/sitemap.xml").get_data(as_text=True)
        self.assertIn("/registrars", xml)

    def test_ref_click_tracking_accepts_registrar(self):
        resp = self.client.post(
            "/track/ref-click",
            json={"type": "registrar", "id": "regru", "placement": "test", "locale": "ru"},
        )
        self.assertEqual(200, resp.status_code)
        self.assertTrue(resp.get_json().get("ok"))


if __name__ == "__main__":
    unittest.main()