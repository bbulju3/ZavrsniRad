const express = require('express');

const cors = require('cors');

const db = require('./db');

const app = express();

const bcrypt = require('bcryptjs');

const jwt = require('jsonwebtoken');

const authMiddleWare = require('./authMidW');

const adminMiddleware = require('./adminMidW');

app.use(cors());

app.use(express.json());

// Helper funkcija za validaciju emaila
const isValidEmail = (email) => {
    // Standardni regex za provjeru osnovnog formata emaila (nesto@nesto.domena)
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

// Helper funkcija za validaciju lozinke
const isValidPassword = (password) => {
    // Mora imati min 8 znakova, barem 1 malo slovo, 1 veliko slovo i 1 broj
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
    return passwordRegex.test(password);
};

app.post('/api/auth/register', async (req, res) => {
    const { ime, prezime, email, lozinka } = req.body;

    if (!ime || !prezime || !email || !lozinka) {
        return res.status(400).json({ greska: 'Sva polja su obavezna.' });
    }

    try {
        const [postojiKorisnik] = await db.query('SELECT id FROM Korisnici WHERE email = ?', [email]);
        if (postojiKorisnik.length > 0) {
            return res.status(400).json({ greska: 'Korisnik s ovim emailom već postoji.' });
        }

        const sol = await bcrypt.genSalt(10);
        const hashiranaLozinka = await bcrypt.hash(lozinka, sol);

        const [result] = await db.query(
            'INSERT INTO Korisnici (ime, prezime, email, lozinka_hash) VALUES (?, ?, ?, ?)',
            [ime, prezime, email, hashiranaLozinka]
        );

        res.status(201).json({ poruka: 'Korisnik uspješno registriran!', korisnikId: result.insertId });
    } catch (error) {
        res.status(500).json({ greska: 'Greška prilikom registracije.', detalji: error.message });
    }
});

//Korisnicki login i token

app.post('/api/auth/login', async (req, res) => {
    const { email, lozinka } = req.body;

    if (!email || !lozinka) {
        return res.status(400).json({ greska: 'Email i lozinka su obavezni.' });
    }

    try {
        const [rows] = await db.query('SELECT * FROM Korisnici WHERE email = ?', [email]);
        if (rows.length === 0) {
            return res.status(401).json({ greska: 'Pogrešan email ili lozinka.' });
        }

        const korisnik = rows[0];

        const lozinkaJeTocna = await bcrypt.compare(lozinka, korisnik.lozinka_hash);
        if (!lozinkaJeTocna) {
            return res.status(401).json({ greska: 'Pogrešan email ili lozinka.' });
        }

        const token = jwt.sign(
            { id: korisnik.id, email: korisnik.email, uloga: 'korisnik' },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(200).json({
            poruka: 'Prijava uspješna!',
            token: token,
            korisnik: {
                id: korisnik.id,
                ime: korisnik.ime,
                prezime: korisnik.prezime,
                email: korisnik.email
            }
        });
    } catch (error) {
        res.status(500).json({ greska: 'Greška prilikom prijave.', detalji: error.message });
    }
});

//Admin login i token

app.post('/api/auth/admin-login', async (req, res) => {
    const { email, lozinka } = req.body;

    if (!email || !lozinka) {
        return res.status(400).json({ greska: 'Email i lozinka su obavezni.' });
    }

    try {
        const [rows] = await db.query('SELECT * FROM Administratori WHERE email = ?', [email]);
        if (rows.length === 0) {
            return res.status(401).json({ greska: 'Pogrešan email ili lozinka.' });
        }

        const admin = rows[0];

        const lozinkaJeTocna = await bcrypt.compare(lozinka, admin.lozinka_hash);
        if (!lozinkaJeTocna) {
            return res.status(401).json({ greska: 'Pogrešan email ili lozinka.' });
        }

        const token = jwt.sign(
            { id: admin.id, email: admin.email, uloga: 'admin' },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(200).json({
            poruka: 'Admin prijava uspješna!',
            token: token,
            admin: {
                id: admin.id,
                ime: admin.ime,
                prezime: admin.prezime,
                email: admin.email
            }
        });
    } catch (error) {
        res.status(500).json({ greska: 'Greška prilikom prijave administratora.', detalji: error.message });
    }
});

// Authorized [UPDATE] - ažuriranje vlastitog korisničkog profila
app.put('/api/auth/korisnik/profil', authMiddleWare, async (req, res) => {
    const korisnik_id = req.user.id;
    const { ime, prezime, email, lozinka } = req.body;

    if (!ime || !prezime || !email) {
        return res.status(400).json({ greska: 'Polja ime, prezime i email su obavezna.' });
    }

    if (!isValidEmail(email)) {
        return res.status(400).json({ greska: 'Neispravan format email adrese.' });
    }

    if (lozinka && !isValidPassword(lozinka)) {
        return res.status(400).json({ greska: 'Nova lozinka mora imati barem 8 znakova, uključujući barem jedno veliko slovo, jedno malo slovo i jedan broj.' });
    }

    try {
        const [postojiEmail] = await db.query('SELECT id FROM Korisnici WHERE email = ? AND id != ?', [email, korisnik_id]);
        if (postojiEmail.length > 0) {
            return res.status(400).json({ greska: 'Uneseni email je već u upotrebi od strane drugog korisnika.' });
        }

        if (lozinka) {
            const sol = await bcrypt.genSalt(10);
            const hashiranaLozinka = await bcrypt.hash(lozinka, sol);

            await db.query(
                'UPDATE Korisnici SET ime = ?, prezime = ?, email = ?, lozinka_hash = ? WHERE id = ?',
                [ime, prezime, email, hashiranaLozinka, korisnik_id]
            );
        } else {
            await db.query(
                'UPDATE Korisnici SET ime = ?, prezime = ?, email = ? WHERE id = ?',
                [ime, prezime, email, korisnik_id]
            );
        }

        res.status(200).json({ poruka: 'Korisnički profil uspješno ažuriran!' });
    } catch (error) {
        res.status(500).json({ greska: 'Greška prilikom ažuriranja profila.', detalji: error.message });
    }
});

// Authorized [CREATE] - rezervacija
app.post('/api/auth/rezervacije', authMiddleWare, async (req, res) => {
    const { resurs_id, vrijeme_pocetka, vrijeme_zavrsetka } = req.body;

    // ID korisnika automatski izvlačimo iz JWT tokena (postavio ga je authMiddleware)
    const korisnik_id = req.user.id;

    if (!resurs_id || !vrijeme_pocetka || !vrijeme_zavrsetka) {
        return res.status(400).json({ greska: 'Sva polja (resurs_id, vrijeme_pocetka, vrijeme_zavrsetka) su obavezna.' });
    }

    // --- TEMPORALNE VALIDACIJE ---
    const start = new Date(vrijeme_pocetka);
    const end = new Date(vrijeme_zavrsetka);
    const now = new Date();

    if (end <= start) {
        return res.status(400).json({ greska: 'Vrijeme završetka mora biti nakon vremena početka.' });
    }
    if (start < now) {
        return res.status(400).json({ greska: 'Nije moguće kreirati rezervaciju u prošlosti.' });
    }

    try {
        const [resursInfo] = await db.query('SELECT tip FROM Resursi WHERE id = ?', [resurs_id]);

        if (resursInfo.length === 0) {
            return res.status(404).json({ greska: 'Traženi resurs ne postoji u bazi.' });
        }

        const tip_resursa = resursInfo[0].tip;

        // --- 1. VALIDACIJA: Provjera ima li korisnik aktivnu zabranu pristupa ---
        const [zabrane] = await db.query(
            'SELECT id, razlog FROM Zabrane_Pristupa WHERE korisnik_id = ? AND aktivna = true AND (resurs_id = ? OR tip_resursa = ?)',
            [korisnik_id, resurs_id, tip_resursa]
        );
        if (zabrane.length > 0) {
            return res.status(403).json({
                greska: 'Rezervacija odbijena. Imate aktivnu zabranu pristupa za ovaj resurs ili tip resursa!',
                razlog: zabrane[0].razlog
            });
        }

        // --- 2. VALIDACIJA: SQL algoritam za preklapanje termina (Double-booking prevention) ---
        const sqlProvjeraPreklapanja = `
            SELECT id FROM Rezervacije 
            WHERE resurs_id = ? 
              AND status = 'aktivna'
              AND vrijeme_pocetka < ? 
              AND vrijeme_zavrsetka > ?
        `;

        // Šaljemo parametre: resurs_id, novi_zavrsetak, novi_pocetak
        const [preklapanja] = await db.query(sqlProvjeraPreklapanja, [resurs_id, vrijeme_zavrsetka, vrijeme_pocetka]);

        if (preklapanja.length > 0) {
            return res.status(409).json({
                greska: 'Termin je zauzet. Odabrani resurs je već rezerviran u navedenom vremenu.'
            });
        }

        // --- 3. IZVRŠAVANJE: Ako su sve provjere prošle, upisujemo rezervaciju ---
        const [result] = await db.query(
            'INSERT INTO Rezervacije (korisnik_id, resurs_id, vrijeme_pocetka, vrijeme_zavrsetka, status) VALUES (?, ?, ?, ?, ?)',
            [korisnik_id, resurs_id, vrijeme_pocetka, vrijeme_zavrsetka, 'aktivna']
        );

        res.status(201).json({
            poruka: 'Rezervacija uspješno kreirana!',
            rezervacijaId: result.insertId
        });

    } catch (error) {
        res.status(500).json({ greska: 'Greška prilikom kreiranja rezervacije.', detalji: error.message });
    }
});

// Authorized [READ] - dohvat svih vlastitih rezervacija korisnika
app.get('/api/auth/korisnik/moje-rezervacije', authMiddleWare, async (req, res) => {
    const korisnik_id = req.user.id; // Izravno i sigurno preuzimanje ID-a iz tokena

    try {
        // Dohvaćamo sve rezervacije za tog korisnika, sortirane tako da su najnovije prve
        const [mojeRezervacije] = await db.query(
            'SELECT * FROM Rezervacije WHERE korisnik_id = ? ORDER BY id DESC',
            [korisnik_id]
        );

        res.status(200).json(mojeRezervacije);
    } catch (error) {
        res.status(500).json({
            greska: 'Greška prilikom dohvaćanja vaših rezervacija.',
            detalji: error.message
        });
    }
});

// Authorized [UPDATE] - rezervacija (promjena termina ili otkazivanje)
app.put('/api/auth/rezervacije/:id', authMiddleWare, async (req, res) => {
    const { id } = req.params; // ID rezervacije koju mijenjamo
    const { vrijeme_pocetka, vrijeme_zavrsetka, status } = req.body;
    const korisnik_id = req.user.id; // Izvlačimo iz tokena radi sigurnosti

    if (!vrijeme_pocetka || !vrijeme_zavrsetka || !status) {
        return res.status(400).json({ greska: 'Sva polja (vrijeme_pocetka, vrijeme_zavrsetka, status) su obavezna.' });
    }

    // --- TEMPORALNE VALIDACIJE ---
    const start = new Date(vrijeme_pocetka);
    const end = new Date(vrijeme_zavrsetka);
    const now = new Date();

    if (end <= start) {
        return res.status(400).json({ greska: 'Vrijeme završetka mora biti nakon vremena početka.' });
    }

    // Zabrana prebacivanja termina u prošlost
    if (start < now) {
        return res.status(400).json({ greska: 'Ne možete premjestiti rezervaciju u termin koji je već prošao.' });
    }

    try {
        // Prvo provjeravamo postoji li rezervacija i pripada li stvarno tom korisniku
        const [provjeraVlasnistva] = await db.query(
            'SELECT resurs_id FROM Rezervacije WHERE id = ? AND korisnik_id = ?',
            [id, korisnik_id]
        );

        if (provjeraVlasnistva.length === 0) {
            return res.status(404).json({ greska: 'Rezervacija nije pronađena ili nemate ovlasti za njezinu izmjenu.' });
        }

        const resurs_id = provjeraVlasnistva[0].resurs_id;

        const [resursInfo] = await db.query('SELECT tip FROM Resursi WHERE id = ?', [resurs_id]);

        if (resursInfo.length === 0) {
            return res.status(404).json({ greska: 'Traženi resurs ne postoji u bazi.' });
        }

        const tip_resursa = resursInfo[0].tip;

        // --- 1. VALIDACIJA: Provjera ima li korisnik aktivnu zabranu pristupa ---
        const [zabrane] = await db.query(
            'SELECT id, razlog FROM Zabrane_Pristupa WHERE korisnik_id = ? AND aktivna = true AND (resurs_id = ? OR tip_resursa = ?)',
            [korisnik_id, resurs_id, tip_resursa]
        );
        if (zabrane.length > 0) {
            return res.status(403).json({
                greska: 'Izmjena odbijena. Imate aktivnu zabranu pristupa za ovaj resurs ili tip resursa!',
                razlog: zabrane[0].razlog
            });
        }

        // --- 2. VALIDACIJA: Provjera preklapanja termina ---
        if (status === 'aktivna') {
            const sqlProvjeraPreklapanja = `
                SELECT id FROM Rezervacije 
                WHERE resurs_id = ? 
                  AND status = 'aktivna'
                  AND id != ?
                  AND vrijeme_pocetka < ? 
                  AND vrijeme_zavrsetka > ?
            `;

            // Proslijeđujemo resurs_id, id trenutne rezervacije (da preskoči samu sebe), zavrsetak i pocetak
            const [preklapanja] = await db.query(sqlProvjeraPreklapanja, [resurs_id, id, vrijeme_zavrsetka, vrijeme_pocetka]);

            if (preklapanja.length > 0) {
                return res.status(409).json({
                    greska: 'Termin je zauzet. Odabrani resurs je već rezerviran u navedenom vremenu.'
                });
            }
        }

        // --- 3. IZVRŠAVANJE: Ažuriranje podataka u bazi ---
        await db.query(
            'UPDATE Rezervacije SET vrijeme_pocetka = ?, vrijeme_zavrsetka = ?, status = ? WHERE id = ? AND korisnik_id = ?',
            [vrijeme_pocetka, vrijeme_zavrsetka, status, id, korisnik_id]
        );

        res.status(200).json({ poruka: 'Rezervacija uspješno ažurirana!' });

    } catch (error) {
        res.status(500).json({ greska: 'Greška prilikom ažuriranja rezervacije.', detalji: error.message });
    }
});

// Authorized [READ] - zabrane
app.get('/api/auth/korisnik/moje-zabrane', authMiddleWare, async (req, res) => {
    const korisnik_id = req.user.id; // Izravno i sigurno preuzimanje ID-a iz tokena

    try {
        // Dohvaćamo sve zabrane za tog korisnika, sortirane tako da su najnovije prve
        const [mojeZabrane] = await db.query(
            'SELECT * FROM Zabrane_Pristupa WHERE korisnik_id = ? ORDER BY id DESC',
            [korisnik_id]
        );

        res.status(200).json(mojeZabrane);
    } catch (error) {
        res.status(500).json({
            greska: 'Greška prilikom dohvaćanja vaših zabrana pristupa.',
            detalji: error.message
        });
    }
});

//tu ce doci authorized read available resource
// Authorized [READ] - resursi bez zabrane
app.get('/api/auth/resursi-dostupni', authMiddleWare, async (req, res) => {
    const korisnik_id = req.user.id; // Izvlačimo ID iz tokena

    try {
        // SQL upit dohvaća sve resurse (r) za koje NE POSTOJI (NOT EXISTS)
        // aktivna zabrana (z) za ovog korisnika koja se odnosi na r.id ILI r.tip

        const sqlDostupniResursi = `
            SELECT r.* FROM Resursi r
            WHERE NOT EXISTS (
                SELECT 1 
                FROM Zabrane_Pristupa z
                WHERE z.korisnik_id = ? 
                  AND z.aktivna = true 
                  AND (z.resurs_id = r.id OR z.tip_resursa = r.tip)
            )
        `;

        const [dostupniResursi] = await db.query(sqlDostupniResursi, [korisnik_id]);
        
        res.status(200).json(dostupniResursi);
    } catch (error) {
        res.status(500).json({ 
            greska: 'Greška prilikom dohvaćanja dostupnih resursa.', 
            detalji: error.message 
        });
    }
});


// Authorized [READ] - resurs-zauzetost
app.get('/api/auth/resursi/:id/zauzetost', authMiddleWare, async (req, res) => {
    const { id } = req.params; // ID resursa za koji tražimo zauzetost

    try {
        // Dohvaćamo samo 'aktivne' rezervacije koje završavaju u budućnosti ili sadašnjosti
        const [zauzetiTermini] = await db.query(
            `SELECT vrijeme_pocetka, vrijeme_zavrsetka 
             FROM Rezervacije 
             WHERE resurs_id = ? 
               AND status = 'aktivna' 
               AND vrijeme_zavrsetka >= NOW()
             ORDER BY vrijeme_pocetka ASC`,
            [id]
        );

        res.status(200).json(zauzetiTermini);
    } catch (error) {
        res.status(500).json({ greska: 'Greška prilikom dohvaćanja rasporeda resursa.', detalji: error.message });
    }
});

// [READ] - korisnici
app.get('/api/korisnici', adminMiddleware, async (req, res) => {
    try {       
    const [rows] = await db.query('SELECT * FROM Korisnici');        
    res.status(200).json(rows);
} catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri dohvaćanju korisnika' }); }
});
// [CREATE] - korisnik
app.post('/api/korisnici', adminMiddleware, async (req, res) => {
    const { ime, prezime, email, lozinka } = req.body;

    if (!email || !isValidEmail(email)) {
        return res.status(400).json({ greska: 'Neispravan format email adrese.' });
    }
    if (!lozinka || !isValidPassword(lozinka)) {
        return res.status(400).json({ greska: 'Lozinka mora imati barem 8 znakova, uključujući barem jedno veliko slovo, jedno malo slovo i jedan broj.' });
    }

    try {
        const hash = await bcrypt.hash(lozinka, 10);
        await db.query('INSERT INTO Korisnici (ime, prezime, email, lozinka_hash) VALUES (?, ?, ?, ?)', [ime, prezime, email, hash]);
        res.status(201).json({ poruka: 'Korisnik uspješno kreiran' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ greska: 'Greška pri kreiranju korisnika' });
    }
});

// [UPDATE] - korisnik
app.put('/api/korisnici/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    const { ime, prezime, email, lozinka } = req.body;

    if (email && !isValidEmail(email)) {
        return res.status(400).json({ greska: 'Neispravan format email adrese.' });
    }
    if (lozinka && !isValidPassword(lozinka)) {
        return res.status(400).json({ greska: 'Nova lozinka mora imati barem 8 znakova, uključujući barem jedno veliko slovo, jedno malo slovo i jedan broj.' });
    }

    try {
        if (lozinka) {
            const hash = await bcrypt.hash(lozinka, 10);
            await db.query('UPDATE Korisnici SET ime = ?, prezime = ?, email = ?, lozinka_hash = ? WHERE id = ?', [ime, prezime, email, hash, id]);
        } else {
            await db.query('UPDATE Korisnici SET ime = ?, prezime = ?, email = ? WHERE id = ?', [ime, prezime, email, id]);
        }
        res.status(200).json({ poruka: 'Korisnički podaci uspješno ažurirani' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ greska: 'Greška pri ažuriranju korisnika' });
    }
});
// [DELETE] - korisnik
app.delete('/api/korisnici/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    try {      
    await db.query('DELETE FROM Korisnici WHERE id = ?', [id]);
    res.status(200).json({ poruka: 'Korisnik uspješno obrisan' });
} catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri brisanju korisnika. Provjerite vanjske ključeve.' }); }
});

// [READ] - administratori
app.get('/api/administratori', adminMiddleware, async (req, res) => {
    try {
    const [rows] = await db.query('SELECT * FROM Administratori');
    res.status(200).json(rows);
} catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri dohvaćanju administratora' }); }
});
// [CREATE] - administrator
app.post('/api/administratori', adminMiddleware, async (req, res) => {
    const { ime, prezime, email, lozinka } = req.body;

    if (!email || !isValidEmail(email)) {
        return res.status(400).json({ greska: 'Neispravan format email adrese.' });
    }
    if (!lozinka || !isValidPassword(lozinka)) {
        return res.status(400).json({ greska: 'Lozinka mora imati barem 8 znakova, uključujući barem jedno veliko slovo, jedno malo slovo i jedan broj.' });
    }

    try {
        const hash = await bcrypt.hash(lozinka, 10);
        const [result] = await db.query('INSERT INTO Administratori (ime, prezime, email, lozinka_hash) VALUES (?, ?, ?, ?)', [ime, prezime, email, hash]);
        res.status(201).json({ poruka: 'Administrator uspješno kreiran', id: result.insertId });
    } catch (error) {
        console.error(error);
        res.status(500).json({ greska: 'Greška pri kreiranju administratora' });
    }
});

// [UPDATE] - administrator
app.put('/api/administratori/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    const { ime, prezime, email, lozinka } = req.body;

    if (email && !isValidEmail(email)) {
        return res.status(400).json({ greska: 'Neispravan format email adrese.' });
    }
    // Provjeravamo lozinku SAMO ako je poslana
    if (lozinka && !isValidPassword(lozinka)) {
        return res.status(400).json({ greska: 'Nova lozinka mora imati barem 8 znakova, uključujući barem jedno veliko slovo, jedno malo slovo i jedan broj.' });
    }

    try {
        if (lozinka) {
            const hash = await bcrypt.hash(lozinka, 10);
            await db.query('UPDATE Administratori SET ime = ?, prezime = ?, email = ?, lozinka_hash = ? WHERE id = ?', [ime, prezime, email, hash, id]);
        } else {
            await db.query('UPDATE Administratori SET ime = ?, prezime = ?, email = ? WHERE id = ?', [ime, prezime, email, id]);
        }
        res.status(200).json({ poruka: 'Administratorski podaci uspješno ažurirani' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ greska: 'Greška pri ažuriranju administratora' });
    }
});
// [DELETE] - administrator
app.delete('/api/administratori/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        await db.query('DELETE FROM Administratori WHERE id = ?', [id]);
        res.status(200).json({ poruka: 'Administrator uspješno obrisan' });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri brisanju administratora' }); }
});

// [READ] - resursi
app.get('/api/resursi', adminMiddleware, async (req, res) => {
    try {
    const [rows] = await db.query('SELECT * FROM Resursi');
    res.status(200).json(rows);
} catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri dohvaćanju resursa' }); }
});
// [CREATE] - resurs
app.post('/api/resursi', adminMiddleware, async (req, res) => {
    const { naziv, tip, opis, kapacitet, status } = req.body;
    try {
        const [result] = await db.query('INSERT INTO Resursi (naziv, tip, opis, kapacitet, status) VALUES (?, ?, ?, ?, ?)', [naziv, tip, opis, kapacitet, status]);
        res.status(201).json({ poruka: 'Resurs uspješno kreiran', id: result.insertId });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri kreiranju resursa' }); }
});
// [UPDATE] - resurs
app.put('/api/resursi/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    const { naziv, tip, opis, kapacitet, status } = req.body;
    try {
        await db.query('UPDATE Resursi SET naziv = ?, tip = ?, opis = ?, kapacitet = ?, status = ? WHERE id = ?', [naziv, tip, opis, kapacitet, status, id]);
        res.status(200).json({ poruka: 'Resurs uspješno ažuriran' });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri ažuriranju resursa' }); }
});
// [DELETE] - resurs
app.delete('/api/resursi/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        await db.query('DELETE FROM Resursi WHERE id = ?', [id]);
        res.status(200).json({ poruka: 'Resurs uspješno obrisan' });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri brisanju resursa. Provjerite postoje li povezane rezervacije.' }); }
});

// [READ] - zabrane
app.get('/api/zabrane', adminMiddleware, async (req, res) => {
    try {
    const [rows] = await db.query('SELECT * FROM Zabrane_Pristupa');
    res.status(200).json(rows);
} catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri dohvaćanju zabrana' }); }
});

// [CREATE] - zabrana
app.post('/api/zabrane', adminMiddleware, async (req, res) => {
    // 1. Vadimo ID admina iz middlewarea (ovisno kako si nazvao ključ u payloadu pri kreiranju tokena)
    const administrator_id = req.user.id || req.user.admin_id;

    // 2. administrator_id je uklonjen iz destrukturiranja req.body
    const { korisnik_id, resurs_id, tip_resursa, razlog, aktivna } = req.body;

    // VALIDACIJA: Provjera isključivosti (XOR logika)
    const imaResurs = resurs_id ? true : false;
    const imaTip = tip_resursa ? true : false;

    if (imaResurs === imaTip) {
        return res.status(400).json({
            greska: 'Neispravan zahtjev. Morate proslijediti isključivo resurs_id ILI tip_resursa. Ne možete oboje i ne možete nijedno.'
        });
    }

    try {
        const siguranResursId = resurs_id || null;
        const siguranTipResursa = tip_resursa || null;

        const [result] = await db.query(
            'INSERT INTO Zabrane_Pristupa (korisnik_id, administrator_id, resurs_id, tip_resursa, razlog, aktivna) VALUES (?, ?, ?, ?, ?, ?)',
            [korisnik_id, administrator_id, siguranResursId, siguranTipResursa, razlog, aktivna !== undefined ? aktivna : true]
        );
        res.status(201).json({ poruka: 'Zabrana uspješno kreirana', id: result.insertId });
    } catch (error) {
        console.error(error);
        res.status(500).json({ greska: 'Greška pri kreiranju zabrane' });
    }
});

// [UPDATE] - zabrana
app.put('/api/zabrane/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;

    // I ovdje vadimo ID admina direktno iz middlewarea
    const administrator_id = req.user.id || req.user.admin_id;

    // administrator_id je uklonjen iz destrukturiranja req.body
    const { korisnik_id, resurs_id, tip_resursa, razlog, aktivna } = req.body;

    // VALIDACIJA
    const imaResurs = resurs_id ? true : false;
    const imaTip = tip_resursa ? true : false;

    if (imaResurs === imaTip) {
        return res.status(400).json({
            greska: 'Neispravan zahtjev. Morate proslijediti isključivo resurs_id ILI tip_resursa.'
        });
    }

    try {
        const siguranResursId = resurs_id || null;
        const siguranTipResursa = tip_resursa || null;

        await db.query(
            'UPDATE Zabrane_Pristupa SET korisnik_id = ?, administrator_id = ?, resurs_id = ?, tip_resursa = ?, razlog = ?, aktivna = ? WHERE id = ?',
            [korisnik_id, administrator_id, siguranResursId, siguranTipResursa, razlog, aktivna, id]
        );
        res.status(200).json({ poruka: 'Zabrana pristupa uspješno ažurirana' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ greska: 'Greška pri ažuriranju zabrane' });
    }
});

// [DELETE] - zabrana
app.delete('/api/zabrane/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        await db.query('DELETE FROM Zabrane_Pristupa WHERE id = ?', [id]);
        res.status(200).json({ poruka: 'Zabrana uspješno obrisana iz baze' });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri brisanju zabrane' }); }
});

// [READ] - rezervacije
app.get('/api/rezervacije', adminMiddleware, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM Rezervacije');
        res.status(200).json(rows);
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri dohvaćanju rezervacija' }); }
});
// [CREATE] - rezervacija (Admin)
app.post('/api/rezervacije', adminMiddleware, async (req, res) => {
    const { korisnik_id, resurs_id, vrijeme_pocetka, vrijeme_zavrsetka, status, napomena_admina } = req.body;

    // Osnovna provjera polja
    if (!korisnik_id || !resurs_id || !vrijeme_pocetka || !vrijeme_zavrsetka) {
        return res.status(400).json({ greska: 'Sva osnovna polja (korisnik_id, resurs_id, vrijeme_pocetka, vrijeme_zavrsetka) su obavezna.' });
    }

    // --- TEMPORALNE VALIDACIJE ---
    const start = new Date(vrijeme_pocetka);
    const end = new Date(vrijeme_zavrsetka);
    const now = new Date();

    if (end <= start) {
        return res.status(400).json({ greska: 'Vrijeme završetka mora biti nakon vremena početka.' });
    }
    if (start < now) {
        return res.status(400).json({ greska: 'Nije moguće kreirati rezervaciju u prošlosti.' });
    }

    try {
        const [resursInfo] = await db.query('SELECT tip FROM Resursi WHERE id = ?', [resurs_id]);

        if (resursInfo.length === 0) {
            return res.status(404).json({ greska: 'Traženi resurs ne postoji u bazi.' });
        }

        const tip_resursa = resursInfo[0].tip;

        // --- 1. VALIDACIJA ZABRANE: Za ciljanog korisnika ---
        const [zabrane] = await db.query(
            'SELECT id, razlog FROM Zabrane_Pristupa WHERE korisnik_id = ? AND aktivna = true AND (resurs_id = ? OR tip_resursa = ?)',
            [korisnik_id, resurs_id, tip_resursa]
        );

        if (zabrane.length > 0) {
            return res.status(403).json({
                greska: 'Korisnik za kojega kreirate rezervaciju ima aktivnu zabranu pristupa!',
                razlog: zabrane[0].razlog
            });
        }

        // --- 2. VALIDACIJA PREKLAPANJA (Double-booking) ---
        const sqlProvjeraPreklapanja = `
            SELECT id FROM Rezervacije 
            WHERE resurs_id = ? 
              AND status = 'aktivna'
              AND vrijeme_pocetka < ? 
              AND vrijeme_zavrsetka > ?
        `;
        const [preklapanja] = await db.query(sqlProvjeraPreklapanja, [resurs_id, vrijeme_zavrsetka, vrijeme_pocetka]);

        if (preklapanja.length > 0) {
            return res.status(409).json({ greska: 'Termin je zauzet. Odabrani resurs je već rezerviran u navedenom vremenu.' });
        }

        // --- 3. IZVRŠAVANJE UPISA ---
        const [result] = await db.query(
            'INSERT INTO Rezervacije (korisnik_id, resurs_id, vrijeme_pocetka, vrijeme_zavrsetka, status, napomena_admina) VALUES (?, ?, ?, ?, ?, ?)',
            [korisnik_id, resurs_id, vrijeme_pocetka, vrijeme_zavrsetka, status || 'aktivna', napomena_admina || null]
        );

        res.status(201).json({ poruka: 'Rezervacija uspješno kreirana', id: result.insertId });

    } catch (error) {
        console.error(error);
        res.status(500).json({ greska: 'Greška pri kreiranju rezervacije' });
    }
});
// [UPDATE] - rezervacija (Admin)
app.put('/api/rezervacije/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    const { korisnik_id, resurs_id, vrijeme_pocetka, vrijeme_zavrsetka, status, napomena_admina } = req.body;

    if (!korisnik_id || !resurs_id || !vrijeme_pocetka || !vrijeme_zavrsetka || !status) {
        return res.status(400).json({ greska: 'Nedostaju obavezni podaci za ažuriranje.' });
    }

    // --- TEMPORALNE VALIDACIJE ---
    const start = new Date(vrijeme_pocetka);
    const end = new Date(vrijeme_zavrsetka);
    const now = new Date();

    if (end <= start) {
        return res.status(400).json({ greska: 'Vrijeme završetka mora biti nakon vremena početka.' });
    }

    // Provjera prošlosti kod ažuriranja
    if (start < now) {
        return res.status(400).json({ greska: 'Ne možete premjestiti rezervaciju u termin koji je već prošao.' });
    }

    try {
        const [resursInfo] = await db.query('SELECT tip FROM Resursi WHERE id = ?', [resurs_id]);

        if (resursInfo.length === 0) {
            return res.status(404).json({ greska: 'Traženi resurs ne postoji u bazi.' });
        }

        const tip_resursa = resursInfo[0].tip;

        // --- 1. VALIDACIJA ZABRANE: Za ciljanog korisnika ---
        const [zabrane] = await db.query(
            'SELECT id, razlog FROM Zabrane_Pristupa WHERE korisnik_id = ? AND aktivna = true AND (resurs_id = ? OR tip_resursa = ?)',
            [korisnik_id, resurs_id, tip_resursa]
        );

        if (zabrane.length > 0) {
            return res.status(403).json({
                greska: 'Odabrani korisnik ima aktivnu zabranu pristupa za ovaj resurs!',
                razlog: zabrane[0].razlog
            });
        }

        // --- 2. VALIDACIJA PREKLAPANJA (Double-booking) ---
        // Provjeravamo preklapanje samo ako je status rezervacije "aktivna"
        if (status === 'aktivna') {
            const sqlProvjeraPreklapanja = `
                SELECT id FROM Rezervacije 
                WHERE resurs_id = ? 
                  AND status = 'aktivna'
                  AND id != ? 
                  AND vrijeme_pocetka < ? 
                  AND vrijeme_zavrsetka > ?
            `;
            const [preklapanja] = await db.query(sqlProvjeraPreklapanja, [resurs_id, id, vrijeme_zavrsetka, vrijeme_pocetka]);

            if (preklapanja.length > 0) {
                return res.status(409).json({ greska: 'Termin je zauzet. Odabrani resurs je već rezerviran u navedenom vremenu.' });
            }
        }

        // --- 3. IZVRŠAVANJE AŽURIRANJA ---
        await db.query(
            'UPDATE Rezervacije SET korisnik_id = ?, resurs_id = ?, vrijeme_pocetka = ?, vrijeme_zavrsetka = ?, status = ?, napomena_admina = ? WHERE id = ?',
            [korisnik_id, resurs_id, vrijeme_pocetka, vrijeme_zavrsetka, status, napomena_admina, id]
        );

        res.status(200).json({ poruka: 'Rezervacija uspješno izmijenjena' });

    } catch (error) {
        console.error(error);
        res.status(500).json({ greska: 'Greška pri izmjeni rezervacije' });
    }
});
// [DELETE] - rezervacija
app.delete('/api/rezervacije/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        await db.query('DELETE FROM Rezervacije WHERE id = ?', [id]);
        res.status(200).json({ poruka: 'Rezervacija uspješno obrisana' });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri brisanju rezervacije' }); }
});

app.get('/', (req, res) => { res.status(200).json({ poruka: 'REST API server je uspješno pokrenut!' }); });

app.get('/api', (req, res) => {
    res.status(200).json({
        poruka: 'Dobrodošli u glavni API direktorij za rezervaciju resursa',
        dostupne_rute: {
            korisnici: '/api/korisnici',
            administratori: '/api/administratori',
            resursi: '/api/resursi',
            zabrane: '/api/zabrane',
            rezervacije: '/api/rezervacije'
        }
    });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => { console.log(` REST API server uspješno pokrenut na portu ${PORT}`); });

module.exports = app;