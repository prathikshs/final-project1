"""
Blacklist Manager
Run this script to add, remove, list, or bulk-load malicious URLs.
Delete this file before handing the project to the client.
"""

import hashlib
import pickle
import os
import sys

BLACKLIST_PATH = "ref.pkl"


def _hash_url(url: str) -> str:
    url = url.strip().lower()
    if url.startswith(("http://", "https://")):
        url = url.split("://", 1)[1]
    url = url.rstrip("/")
    return hashlib.sha256(url.encode()).hexdigest()


def _load() -> set:
    if not os.path.exists(BLACKLIST_PATH):
        return set()
    try:
        with open(BLACKLIST_PATH, "rb") as f:
            data = pickle.load(f)
        return data if isinstance(data, set) else set()
    except Exception:
        return set()


def _save(bl: set):
    with open(BLACKLIST_PATH, "wb") as f:
        pickle.dump(bl, f)


def add_url(url: str):
    bl = _load()
    h  = _hash_url(url)
    if h in bl:
        print(f"  Already in blacklist: {url}")
    else:
        bl.add(h)
        _save(bl)
        print(f"  Added: {url}")


def remove_url(url: str):
    bl = _load()
    h  = _hash_url(url)
    if h not in bl:
        print(f"  Not found in blacklist: {url}")
    else:
        bl.discard(h)
        _save(bl)
        print(f"  Removed: {url}")


def bulk_add(urls: list):
    bl    = _load()
    added = 0
    for url in urls:
        url = url.strip()
        if not url:
            continue
        h = _hash_url(url)
        if h not in bl:
            bl.add(h)
            added += 1
    _save(bl)
    print(f"  Bulk add complete — {added} new entries added. Total: {len(bl)}")


def count():
    bl = _load()
    print(f"  Total blacklisted URLs: {len(bl)}")


def clear_all():
    confirm = input("  This will delete ALL blacklist entries. Type YES to confirm: ")
    if confirm.strip() == "YES":
        _save(set())
        print("  Blacklist cleared.")
    else:
        print("  Cancelled.")


# ── Pre-loaded malicious URLs from dataset ────────────────────────────────────

MALICIOUS_URLS = [
    "petrepes.com/GRcntrlde/_webscr.php",
    "www.belotti.fr/bill/en.php",
    "oupctvblrq.duckdns.org/ja/main",
    "www.dsbox.com/minigl.html",
    "www.aosnsuuuauuusosu.akczkyr.presse.ci/AU/page1.php",
    "rikuzentakata-mpf.org/67fgbcni",
    "www.heartofcampusministry.com/config/genDoc2.html",
    "www.kaitystein.com/blog/profile/",
    "b-triple-t.com",
    "cxzgfg.gtc6kv62.cn/",
    "www.mail.stedelijklyceumexpo.be/beelden/raiffeisen",
    "aeongyfv.boxc6.top/jp",
    "www.forms.gle/ump6xSeUw8eRewNf9",
    "folueaport.top/read.php",
    "deinehardware.eu",
    "bentglasgow.co.uk",
    "hvcu-sec.web.app/",
    "przeniec.eu/review/",
    "kjfhds.wdyceza.cn",
    "klincz.pl/includes/js/123/Paypal_Virefication",
    "www.masamoecri.icu/",
    "rakuten.co.jp.yekvtem.xyz/",
    "kinntoreman.com/applicant/home.php",
    "groups.yahoo.com/group/gem-announce/",
    "tman.insec.org.np",
    "raurkemu.co.jp.ty1mm6wp.cn/",
    "wowshitennoji.com//sharee/sharepoint-3D7/",
    "acomputerexpert.com/act/googledrive/contactform.php",
    "anatanft-free.xyz",
    "acoucam.ga",
    "www.bizine.com/creative",
    "www.dream-floor.co.jp/uopsmeiw9/cb-pc-ver.php",
    "kjgbv.jhongmd.cn",
    "www.boxofficegh.com/~be/paypal/_webscr1.php",
    "www.pls-print.com/images/index.htm",
    "internasjonaluke.org/sapphire/profiler/chase",
    "novatekit.com/newart/3022a68db585c48288b9c236899cca7c/new",
    "www.eki.myownpersonalcoach.com/",
    "http://148.204.63.249/users/sign_in",
    "www.user-amazon.cz-8.top/",
    "surubiproducciones.com/wp/wp-includes/ID3/111/jpg/art/new/",
    "173.243.112.79/ani/ani1/cp.php",
    "www.aeocsen-aesmmen.wmdzkkz.ne.pw/",
    "hggs.jhrxbpp.cn",
    "www.softether.com.cn/js/",
    "www2.etc-meisai.jp.rtyned.shop/",
    "breesoellner.com/w/gdoc/gdoc/",
    "ubz.com.ua/plugins/system/ossystem/com_loader.jpg",
    "www.mcanerin.com/en/search-engine/robots-txt.asp",
    "cot.poliupg.ac.id/wp-content/plugins/tempcleaner/indexss.php",
    "amacon.co/",
    "citeseerx.ist.psu.edu/viewdoc/summary",
    "cromptonbrothers.com/past/sg/auth0user.cgi",
    "www.e.mecsori.com/",
    "amazon-bgyt.yourtrap.com/",
    "jfgcv.bthuqqm.cn/",
    "ame-toko.net/wp-includes/SimplePie/Decode/HTML/trubas/mkbnew/signin.php/",
    "https://agrover.uz/.well-known/pki-validation/bancor",
    "watery.twjingmen.cn/thrill",
    "okmgnfbkkmaew.top/jp",
    "weekendprime.com/towns/onlin",
    "pastehtml.com/view/beyklk6mf.html",
    "ac.miccearod.com",
    "jghcvf.hnkszxu.cn/",
    "ukworktopsdirect.co.uk/updating/home/",
    "windows-offer.com/remax/index.htm",
    "vzapase.ru/wp-content/subscrible/index.php",
    "www2.smdcnacurd.icu/",
    "taxa-account-japana.top/lanjie.php",
    "www.amazon.co.jp.gqhbkh.ph/",
    "www.coperbyte.co.in/Revolutionguruupdated/Images/verif/myaccount/signin/",
    "remit.000webhostapp.com",
    "www.smdc-aeod.txshmgz.presse.ci/",
    "www2.etc-meibashang.ga/",
    "lakoner.com/nl/verify",
    "yodobash.curtain-story.com/",
    "www.rakuten.co.jp.bdnvgsc.cf",
    "setanalasroban.com/r/lwguzdEAppebCkfb",
    "raokvten.roakentu.com/",
    "tour.ts768.cn/glass",
    "classicrunners.co.tz/themes/doc/index.php",
    "justenmarketing.com/machform/hooks/files/",
    "loginaccountsdirect.whostas.com/indexusa/update-account",
    "pastehtml.com/view/bfndku9ar.html",
    "amaozn.ctsrs.com/",
    "ohlalafotografia.com.br/alibaba",
    "https://willyardlaw.com//wp-includes/php/",
    "naturalgustcatering.ro/wp-content/plugins/tags.php",
    "www.rebrand.ly/668b5",
    "rakutenux.nxswa.net/",
    "human.ba/components/com_madmenu/stat/index.htm",
    "metsuyampnb198909.shortcm.li/IbxczP",
    "www.tinymux.org/wiki",
    "www.mobilesuica.jp-ui-co.buzz/",
    "yourga.com.au/encore/airnet/index.php",
    "fotoidea.com/sport/4x4_san_ponso/slides/IMG_9445.html",
    "co.jp-smbclcfx9r57nptllbrsfuta.ua7v24.cn",
    "radiocolocolo.cl/DHL/DHLExpress/",
    "www2.dircets-smbc.co.jplogin.liphdin.cn/",
    "amoueaom-cc-jp.twenergy.cn/",
    "netcubeinter.co.za/includes/acotin/mail.htm",
    "www.veisacvi-visaosmen.dfhozdv.museum.mw",
    "www.dream-floor.co.jp/uopsmeiw9/cb-pc-ver.php",
    "novatekit.com/newart/3022a68db585c48288b9c236899cca7c/new",
    "docomo.jpgi.xyz/",
    "www.inklineglobal.com/products/vdp/",
    "viewsnet.co.jp.duygcs.bar/",
    "kjfgcv.zhujang.cn/",
    "www.rmv-995470242.adventistgh.org/gate.html",
    "www.amazon.mkjhbr.vip/gp/css/homepage.html",
    "www.eki-net-vipstoke.info",
    "pastehtml.com/view/bfndku9ar.html",
    "http://pastehtml.com/view/bc7vg5oqk.html",
    "account.rkuten.co.jp.login.jpa89aaf32hfoia89w2f8w.com/rms/nid/loginfwdi",
    "wilirots.biz/amcntrlde/webscr_prim.php",
    "vegasorder.com/vvon1xzn",
    "ecords.h1363.com/ap/index.php",
    "www.nhk.plus.zigzagweeklynews.com/",
    "www.eki-net-member.qszwvxq.cn/",
    "tools.ietf.org/html/rfc32",
    "www.onjava.com/pub/a/onjava/2002/04/10/jdbc.html",
    "actualizabaidireto.wixsite.com/bai-directo",
    "www.usdoj.gov/crt/ada/certcode.htm",
    "jp-rakuten.x1k.top/",
    "68.170.52.35/vpic21.png",
    "www.ib2.bradesco.com.br-autenticacao-ipbf-login-www.bradesco.com.br.livewebis.com/bradesco/index.html",
    "http://nortiainteriors.com.au/wp-content/plugins/fresco-master/js/61cdb4adfa677f735fd0e0e40c12abd2/way.php",
    "outlook-mailo.se/b7eb6ab0bd337d17df287038f797dcee/revalidate.htm",
    "jr-poueki.3utilities.com",
    "totemhabbo.rel7.com/",
    "www.satisfiability.org/SAT04/",
    "www.ise.ncsu.edu/jwilson/page3.html",
    "hgtbluegrass.com",
    "rakutenux.nxswa.net/",
    "www.asoasmeosmnasen.tufuwxu.presse.ci/",
    "eki-nee.shop/",
    "www.wcomhost.com/Ameli-Assurance/remboursement/login",
    "storageapi-stg.fleek.co/09e4262f-8563-42c8-80d1-7811834da5e7-bucket/rr.html",
    "cidbs.com/mail/account~verification/Email~Quota.php",
    "www.viccats.camcam.dns-cloud.net/Verify/YahooVerification",
    "dflty1.solidwebhost.com/Gorengoup-drive-account-meldrikation",
    "pzhpmp.webwave.dev/",
    "www.ana.co.jp.ekcbtjh.cn/",
    "cromptonbrothers.com/past/sg/auth0user.cgi",
    "www.e.mecsori.com/",
    "olx-pt.orange-trade.site/j/1741102929",
    "n40l.wikia.com/wiki/HP_MicroServer_N40L_Wiki",
    "azanzm.co.ip.creter.club/PondWallty.php",
    "www.cisema.com.cn/login.htm",
    "www.000p4en.wcomhost.com/Ameli-Assurance/remboursement/login",
    "support.eki-cc.cn/",
    "http://videosfacebook.today/app/facebook.com/",
    "www.gmbmedbrokers.com/index.html",
    "5first.com/cgi-bin/mt/alt-tmpl/altmpl/3/",
    "itm64736589365.0fees.org/",
    "amazon-bgyt.yourtrap.com/",
    "jfgcv.bthuqqm.cn/",
    "www.aacouu-aaosoemsouuuqq.kankb.cn",
    "www.masamoecri.icu/",
    "gcresidencial.com//wp-admin/user/jp/source-amz/",
    "www1.my-jcb.cacsncnd.com/",
    "pastehtml.com/view/beyklk6mf.html",
    "ac.miccearod.com",
    "www874.paypal.ca.93285.securessl-150.mx/js/web.apps/ca/m.pp/",
    "https://ifttt.com/recipes/86680",
    "http://thegastonhouse.com/suuport",
    "www.rmv-995470242.adventistgh.org/gate.html",
    "www.amazon.mkjhbr.vip/gp/css/homepage.html",
    "eki-net.oidfind.shop/",
    "help-center513.crabdance.com/verify",
    "support.eki-cc.cn/",
    "www.s.mcsnreri.com",
    "kouklaboutique.000webhostapp.com",
    "easycsms.com/big/auth.sso.biglobe.ne.jp/index.php",
    "www.linas.org/linux/index.html",
    "giga.com.hk/nabb/2/index.htm",
    "www.tibia.community.konoha_anbu_members.w.interia.pl/index.html",
    "members.tripod.com/ChangeGuru/",
    "cpc.cx/57A",
    "rakuten.co.jp.yekvtem.xyz/",
    "www.wmdzkkz.ne.pw/",
    "www.boxofficegh.com/~be/paypal/_webscr1.php",
    "saggi.candles-shop.us/pp/webscr.php",
    "www.impresadeambrosis.it/HJghjb54",
    "3273d2fe9df6c667798f.cloud-platform.info/d4c98643d9255f164837.html",
    "centrogimnasia.com/pdf/adobe/",
    "www.nondot.org/sabre/os/articles",
    "kuza.me/http-djsjdialmbmgnuuucgsgycydsgbnkfjf",
    "www.jeiws.xyz/",
    "aiuy.kdda.rin2zpd8.cn",
    "www.duffywholesalers.com/wp-config.php",
    "agencebp04.firebaseapp.com/",
    "etc.lvcou.cn/",
    "ericacisneros.com/counter/",
    "www.mascesrocd-aosmsoamsncord.xtanlrg.ne.pw",
    "neesandvos.com/wp/tmp/ahdgfhhd.php",
]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python manage_blacklist.py add <url>")
        print("  python manage_blacklist.py remove <url>")
        print("  python manage_blacklist.py count")
        print("  python manage_blacklist.py load_defaults")
        print("  python manage_blacklist.py clear")
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "add" and len(sys.argv) >= 3:
        add_url(sys.argv[2])

    elif cmd == "remove" and len(sys.argv) >= 3:
        remove_url(sys.argv[2])

    elif cmd == "count":
        count()

    elif cmd == "load_defaults":
        print(f"  Loading {len(MALICIOUS_URLS)} default malicious URLs...")
        bulk_add(MALICIOUS_URLS)

    elif cmd == "clear":
        clear_all()

    else:
        print(f"  Unknown command: {cmd}")