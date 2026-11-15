# Kurulum Rehberi (Firebase + GitHub Pages)

Tamamen ücretsiz katmanla (Firebase Spark planı) çalışır. Sunucu yazmanız gerekmez.

## Site nasıl çalışıyor?

1. YouTube'dan (veya başka yerden) gelen ziyaretçi **karşılama + giriş/kayıt** ekranını görür. İçerik görünmez.
2. Kayıt olunca **tam ekran e-posta doğrulama** ekranı açılır. Kullanıcı bağlantıya tıklayıp sayfaya dönünce
   doğrulama otomatik algılanır (6 sn'de bir kontrol + sekmeye dönünce kontrol).
3. Doğrulanınca üç sekme açılır:
   - **✦ Promptlar:** prompt, resim, dosya, video (YouTube) ve link içerikleri; arama + tür filtresi.
   - **💬 Mesajlar:** üyeler arası mesajlaşma (30 sn aralıkla).
   - **⚙ Yönetim:** moderatör ve Kurucuya görünür. İçerik ekleme ve kullanıcı yönetimi **yalnızca Kurucuda**.

| Katman | Ne yapar |
|---|---|
| **Firebase Auth** | E-posta + şifre ile giriş. Şifreler Google'da güvenle saklanır, kodda hiçbir şifre yoktur. |
| **Firestore Rules** (`firestore.rules`) | Tüm yetki kararlarını **sunucuda** verir. İçerik, giriş yapmış **ve** e-postası doğrulanmış kullanıcıya açılır. |
| **App Check + reCAPTCHA v3** | Veritabanına yalnızca **sizin sitenizden** gelen istekleri kabul eder; botların API'ye doğrudan istek atmasını engeller. |
| **Kurucu (Owner)** | `owners/{uid}` belgesi olan hesap. Bu belge yalnızca Firebase Konsolundan oluşturulabilir. |

Roller:
- **Kurucu:** içerik ekle/sil, moderatör ekle/çıkar, ban at/kaldır, tüm mesajları sil.
- **Moderatör:** yalnızca mesaj silebilir. İçerik ekleme, rol verme ve ban yetkisi yoktur.
- **Üye:** doğrulanmış e-posta ile içerikleri görür, 30 sn aralıkla mesaj yazar.

> **Neden "gizli şifre/token" kodda durmuyor?** GitHub Pages'te `script.js` herkese açıktır. İçine koyduğunuz her sır
> herkes tarafından görülür. Bu yüzden Kurucu kimliği kodda değil, Firebase'de tutulur: Kurucu = şifresini yalnızca sizin
> bildiğiniz bir Firebase hesabı + konsolda sizin elinizle eklenen `owners` kaydı.

---

## Adım 1 — Firebase projesi

1. https://console.firebase.google.com → **Add project** (Analytics'i kapatabilirsiniz).
2. Proje Genel Bakış → **Web (`</>`)** simgesi → uygulama adı verin → **Register app**.
3. Çıkan `firebaseConfig` değerlerini `script.js` dosyasının en üstündeki `firebaseConfig` alanına yapıştırın.

## Adım 2 — Authentication

1. **Build → Authentication → Get started → Sign-in method → Email/Password → Enable**.
2. **Settings → Authorized domains → Add domain:** `KULLANICIADI.github.io` (kendi adresiniz).
3. (İsteğe bağlı) **Templates → Email address verification** bölümünden doğrulama e-postasını Türkçeleştirebilirsiniz.

## Adım 3 — Firestore

1. **Build → Firestore Database → Create database** (production mode, size yakın bölge).
2. **Rules** sekmesi → `firestore.rules` dosyasının içeriğinin tamamını yapıştırın → **Publish**.

## Adım 4 — Bot koruması (App Check + reCAPTCHA v3)

1. https://www.google.com/recaptcha/admin → **Create** → tür: **reCAPTCHA v3** → domain'ler:
   `KULLANICIADI.github.io` ve test için `localhost`.
2. **Site key**'i `script.js` içindeki `RECAPTCHA_SITE_KEY` alanına yazın.
3. **Secret key**'i Firebase Konsolu → **App Check → Apps → Web uygulamanız → reCAPTCHA → Register** kısmına yapıştırın.
   (Secret key'i asla koda yazmayın.)
4. Siteyi birkaç kez açıp giriş yapın; App Check → **APIs** sekmesinde isteklerin "verified" göründüğünü doğrulayın.
5. **App Check → APIs → Cloud Firestore → Enforce** deyin. Artık sitenizin dışından gelen istekler reddedilir.
   - Authentication için App Check'i zorunlu kılmak Identity Platform'a geçişi gerektirebilir; zorunlu değildir,
     çünkü profil belgesi (Firestore) olmayan hesap hiçbir şeye erişemez.
6. Yerelde (`localhost`) test ederken konsolda bir **debug token** yazdırılır; onu App Check → Apps → ⋮ → **Manage debug tokens** kısmına ekleyin.

## Adım 5 — GitHub Pages'e yükleme

1. GitHub'da yeni bir repo açın.
2. `index.html`, `style.css`, `script.js` dosyalarını repoya yükleyin (`firestore.rules`, `KURULUM.md` isteğe bağlı).
3. **Settings → Pages → Branch: `main` / `(root)` → Save.**
4. Birkaç dakika sonra `https://KULLANICIADI.github.io/REPO/` adresinde yayında olur.
   (reCAPTCHA ve Authorized domains ayarlarında `KULLANICIADI.github.io` yazmanız yeterlidir.)

## Adım 6 — Kendinizi Kurucu yapın (en önemli adım)

1. Sitede **normal kayıt olun** (güçlü, benzersiz bir şifre kullanın) ve e-postanızı doğrulayın.
2. Firebase Konsolu → **Authentication → Users** → hesabınızın **User UID** değerini kopyalayın.
3. **Firestore Database → Start collection**
   - Collection ID: `owners`
   - Document ID: **kopyaladığınız UID**
   - Alan: `active` (boolean) = `true` → **Save**
4. Siteyi yenileyin: rozetiniz **Kurucu** olur, **⚙ Yönetim** sekmesi açılır.

Bu belgeyi istemciden hiç kimse oluşturamaz (kurallarda `allow write: if false`). Başka birinin Kurucu olmasının tek yolu
sizin Firebase hesabınıza erişmesidir; Google hesabınızı 2 adımlı doğrulama ile koruyun.

## Adım 7 — İçerik ekleme (Kurucu)

**⚙ Yönetim → İçerik ekle** formundan:

| Tür | Ne girilir | Nasıl saklanır |
|---|---|---|
| **Prompt** | Metin (en fazla 8000 karakter) | Firestore; ziyaretçi **Kopyala** düğmesiyle alır |
| **Resim** | JPG/PNG/WEBP | Tarayıcıda otomatik küçültülüp JPEG'e çevrilir (≤ ~700 KB), Firestore'da saklanır |
| **Dosya** | pdf, zip, txt, md, json, csv, docx, xlsx, pptx — en fazla **700 KB** | Firestore; **İndir** düğmesiyle iner |
| **Video** | YouTube bağlantısı | Yalnızca video kimliği saklanır; `youtube-nocookie.com` ile gömülür |
| **Link** | `https://…` bağlantı | Sadece `https` kabul edilir |

**Neden Firebase Storage değil?** Firebase Storage genellikle ücretli (Blaze) plan ister. Ücretsiz kalmak için resim ve küçük
dosyalar Firestore'da, erişim kurallarının arkasında tutulur. Daha büyük dosyalar için **Link** türüyle Google Drive / Mega
vb. bağlantısı ekleyin. Dikkat: bağlantıyı yalnızca giriş yapanlar *görür*, ama bağlantıyı bilen biri doğrudan açabilir.

## Adım 8 — Test listesi

- Çıkış yapıp siteyi açın → yalnızca karşılama + giriş ekranı görünmeli; içerik görünmemeli.
- Yeni hesap açın → tam ekran doğrulama ekranı gelmeli; e-postadaki bağlantıya tıklayınca sayfa kendiliğinden ilerlemeli.
- Doğrulanmamış hesabın tarayıcı konsolundan `content` okumayı deneyin → `permission-denied` almalısınız.
- Üye hesapta **⚙ Yönetim** sekmesi görünmemeli. Konsoldan `content`'e yazmayı deneyin → reddedilmeli.
- Kurucu ile prompt / resim / dosya / video / link ekleyin; üye hesapta görünüp çalıştığını doğrulayın.
- Banlayın → hesap "yasaklandı" ekranına düşmeli.

---

## Güvenlik notları (dürüst sınırlar)

- **İstemci tarafı temizleme güvenlik sınırı değildir.** `script.js` içindeki `sanitize*` fonksiyonları, kullanıcı deneyimi
  ve savunma derinliği içindir. Asıl sınır: (1) tüm veri `textContent` ile gösterilir (HTML olarak yorumlanmaz),
  (2) `index.html` içindeki CSP, (3) Firestore kurallarındaki tür/uzunluk/alan doğrulaması.
- **Prompt metinlerindeki `<` `>` korunur** (ör. `<system>` gibi etiketler) çünkü metin hiçbir zaman HTML olarak yazılmaz.
- **Dosyalar sayfada açılmaz, indirilir** (`application/octet-stream`); HTML/SVG/EXE türleri izin listesinde yoktur.
  Resimler tuvalde yeniden çizilip JPEG'e çevrildiği için içlerindeki gizli veri atılır.
- **Erişim kontrolünün sınırı:** İçerik yalnızca giriş + doğrulanmış e-posta ile okunabilir; ama bir üye gördüğü içeriği kopyalayıp
  paylaşabilir. Bunu hiçbir web sitesi engelleyemez.
- **SQL/NoSQL injection:** Firestore'da sorgu metni birleştirme yoktur; veriler tipli alanlardır ve kurallar tipi/uzunluğu doğrular.
- **Honeypot, hız kontrolü, giriş kilidi** (istemcide) sadece ilk filtredir; botlar atlayabilir. Gerçek koruma:
  App Check, e-posta doğrulama şartı ve sunucu taraflı 30 sn hız sınırıdır.
- **Cloudflare Turnstile** statik sitede tek başına işe yaramaz: token'ı doğrulamak için bir sunucu (ör. Cloudflare Worker) gerekir.
  Bu yüzden Firebase'in sunucusuz çalışan App Check çözümü kullanıldı.
- **Ban, hesap bazlıdır.** Statik barındırmada IP yasağı yapılamaz; biri yeni e-postayla yeni hesap açabilir.
  E-posta doğrulama + App Check bunu zorlaştırır ama imkânsız kılmaz.
- **Kota:** Spark planında Firestore günlük yaklaşık 50 bin okuma / 20 bin yazma sunar. Her resim/dosya görüntüleme 1 okumadır
  (sayfa yüklemesinde değil, düğmeye basınca okunur). Kota aşılırsa istekler durur, ücret kesilmez.
- Firebase SDK sürümü `script.js` içinde `11.0.2` olarak sabitlenmiştir; güncellemek için `import` satırlarındaki sürümü değiştirin.
- Moderatörlere de içerik ekleme yetkisi vermek isterseniz `firestore.rules` içindeki `content` ve `contentData` bölümlerinde
  `isOwner()` yanına `|| isMod()` eklemeniz ve `script.js`'deki `state.isOwner` kontrollerini güncellemeniz gerekir.
