# groupchat 🔒

Szyfrowany czat grupowy peer-to-peer na telefon. Bez kont, bez numeru telefonu, bez serwera, który przechowuje wiadomości.

## Co potrafi

- **Własny numer groupchat** (1–10 cyfr) i **nick**. Numer jest losowany przy pierwszym uruchomieniu albo wpisujesz własny. Działa to jak numer na Gadu-Gadu.
- **Dodawanie znajomych**: wysyłasz swój numer SMS-em (przycisk w profilu). Znajomy klika link w SMS-ie albo wpisuje numer, a ty akceptujesz jego prośbę.
- **Kod weryfikacyjny** (np. `GPWV-HC26`): numer może sobie wymyślić każdy, ale kodu nie da się podrobić. Link w SMS-ie sprawdza kod automatycznie.
- **Główna grupa „Bizzy Pizzy 🍕”**: każdy, kto otworzy aplikację, jest w niej automatycznie (jak grupa na Telegramie). Przypięta na górze listy.
- **Czaty grupowe i prywatne** z dowolną liczbą osób. Zapraszasz z kontaktów albo **linkiem SMS-em** (👥 → „Zaproś linkiem”); link wpuszcza do grupy, ale bez kodu rozmowy nikt nic nie odczyta.
- **Rozmowy grupowe głosowe i wideo** (📞 w nagłówku grupy). Każdy dostaje zaproszenie i może dołączyć także później. Najlepiej działa do 6 osób.
- **Zdjęcia** (zmniejszane do 1600 px) i **filmiki do 30 s**. Duże filmiki aplikacja próbuje skompresować do ok. 480p; limit wynosi 50 MB.
- **Rozmowy głosowe i wideo** między dodanymi kontaktami (wyciszenie, wyłączenie kamery, przełączanie przód/tył).
- **Kod rozmowy (obowiązkowy, z wzajemnym zatwierdzeniem):** każdy czat jest zablokowany, dopóki obie strony nie zatwierdzą tego samego kodu:
  **1. Zadzwoń** do rozmówcy (zwykłym telefonem albo w groupchat) → **2. Kod** (12 cyfr w 4 polach; wylosowany, ale każdą cyfrę możesz poprawić) → **3. Podyktuj** go na głos → **4. Zatwierdź** → rozmówca wpisuje kod i **zatwierdza** → dopiero wtedy obie strony mogą pisać.
  Poprawki na każdym etapie: przed zatwierdzeniem zmieniasz cyfry w polach; po zatwierdzeniem, a przed potwierdzeniem przez rozmówcę, masz przycisk **✏️ Popraw kod**; rozmówca może poprawić pojedyncze pola, a jeśli wpisze kod sprzed poprawki, aplikacja powie, że to poprzedni kod. Później kod zmienisz przyciskiem 🔐 w nagłówku (lista pokazuje, kto potwierdził kod, a kto nie).
  Bez kodu nikt nie odczyta wiadomości, zdjęć ani filmików, nawet z zaproszeniem do grupy. Zmiana kodu jest podpisana poprzednim kodem, więc nikt bez kodu jej nie podrobi.
- **Kod połączenia w rozmowach głosowych i wideo:** obie osoby widzą 6 cyfr wyliczonych z kluczy połączenia. Powiedzcie je sobie: jeśli się różnią, ktoś się wpiął w połączenie, więc rozłącz się.
- **Wiadomości zostają** (historia, zdjęcia i filmiki zapisują się na telefonie, zaszyfrowane). Pod swoją wiadomością masz pytanie **„⏱ Ma zniknąć?”**: po potwierdzeniu znika u wszystkich za 10 minut.
- **PIN aplikacji** (Profil → 🔒): wszystko, co aplikacja zapisuje na telefonie, jest szyfrowane kluczem z PIN-u (PBKDF2, 600 000 iteracji). Blokada po 2 min w tle, rozmyty podgląd w przełączniku aplikacji, opcjonalne kasowanie danych po 10 błędnych PIN-ach.
- **Serwer TURN** (Profil → 🛠️ Połączenie): wklejasz konfigurację z darmowego konta Metered/ExpressTURN, testujesz i zapisujesz. Potrzebny, gdy sieć komórkowa blokuje połączenia bezpośrednie.
- **Pamięta ustawienia**: numer, nick, kontakty, grupy, ustawienia i klucz tożsamości zostają w telefonie.

## Jak to działa (bezpieczeństwo)

| Element | Jak |
|---|---|
| Wiadomości, zdjęcia, filmiki, rozmowy | Idą bezpośrednio między telefonami (WebRTC, szyfrowanie DTLS-SRTP z kluczami jednorazowymi). |
| Treść czatu | Dodatkowo szyfrowana **AES-256-GCM** kluczem z dwóch składników: losowego sekretu grupy (192 bity) i **kodu rozmowy podanego przez telefon** (12 cyfr, PBKDF2-SHA256, 600 000 iteracji). Żeby odczytać rozmowę, trzeba mieć oba. |
| „Zapoznanie” telefonów | Przez publiczne relaye Nostr. Relaye widzą tylko zaszyfrowane, podpisane pakiety i skróty nazw pokoi, a nie treść ani kto z kim pisze. |
| Tożsamość | Każdy telefon ma własny klucz ECDSA. Kod weryfikacyjny to skrót tego klucza, więc nikt nie podszyje się pod znajomego, który już jest w kontaktach. |

**Ograniczenia (uczciwie):**

- Ten program **nie przeszedł audytu bezpieczeństwa** jak Signal. Jeśli od poufności zależy coś naprawdę poważnego, użyj Signala, SimpleX albo Briar.
- Osoby w jednej rozmowie widzą nawzajem swój **adres IP** (tak działa każde połączenie bezpośrednie).
- **Brak skrzynki offline**: wiadomość dotrze tylko do osób, które mają w tej chwili otwartą aplikację. Osoba, która wejdzie później, dostanie ostatnie wiadomości tekstowe od kogoś, kto jest online. Zdjęć i filmików nie dostanie.
- **Główna grupa jest „publiczna” dla wszystkich z aplikacją**: każdy, kto ma link do aplikacji, widzi, kto jest w niej online (nick, numer). Treść chroni kod rozmowy.
- Połączenie przychodzące zadzwoni tylko wtedy, gdy aplikacja jest otwarta albo niedawno była w tle. Android usypia karty po kilku minutach.
- W niektórych sieciach komórkowych (CGNAT) bezpośrednie połączenie się nie uda. Pomaga serwer TURN: Profil → Zaawansowane.
- Ktoś, kto zna twój numer, może wysłać ci prośbę o kontakt (tak jak na GG). Bez twojej akceptacji nic więcej nie zrobi.

## Uruchomienie na telefonie (ok. 10 min, za darmo)

Aplikacja musi być pod adresem **https://** (tego wymaga przeglądarka dla kamery, mikrofonu i szyfrowania). Najprościej przez GitHub Pages:

1. Załóż konto na **github.com** (można z telefonu).
2. Kliknij **+ → New repository**, nazwij je np. `groupchat`, zaznacz **Public**, potem **Create**.
3. **Add file → Upload files** i wrzuć wszystkie pliki z tego folderu: `index.html`, `sw.js`, `manifest.webmanifest`, `icon.svg`, `icon-192.png`, `icon-512.png`. Na koniec **Commit**.
4. Wejdź w **Settings → Pages → Branch: main → / (root) → Save**.
5. Po 1–2 minutach aplikacja jest pod adresem `https://TWOJA-NAZWA.github.io/groupchat/`.
6. Otwórz ten adres w Chrome na telefonie, potem **⋮ → Dodaj do ekranu głównego / Zainstaluj aplikację**. Od tej pory groupchat ma ikonę jak normalna aplikacja.
7. W aplikacji: **Profil → Wyślij mój numer SMS-em**. W SMS-ie jest link, więc znajomy kliknie i od razu cię doda.

Inne darmowe hostingi też zadziałają (Netlify, Cloudflare Pages). Wystarczy wrzucić te same pliki.

**Ważne:** wszyscy znajomi muszą używać aplikacji z **tego samego adresu**, który wyślesz im w SMS-ie.

## Wskazówki

- Filmiki nagrywaj w 720p, wtedy wysyłają się szybko.
- Kody weryfikacyjne porównajcie przy spotkaniu (Kontakty → dotknij osoby).
- Profil → **Włącz powiadomienia**, żeby telefon zawibrował przy nowej wiadomości. Powiadomienie nie pokazuje treści.
- Profil → **Usuń wszystkie dane z telefonu** czyści numer, kontakty i grupy.

Technologia: WebRTC + [Trystero](https://github.com/dmotz/trystero) (sygnalizacja Nostr), Web Crypto API. Całość jest w jednym pliku `index.html` (biblioteki są wbudowane, bez CDN).
