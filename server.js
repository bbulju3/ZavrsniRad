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
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

// Helper funkcija za validaciju lozinke
const isValidPassword = (password) => {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
    return passwordRegex.test(password);
};

// RUTA - User login i token
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

// RUTA - Admin login i token
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

// RUTA - User [UPDATE] korisnik
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

// RUTA - User [CREATE] rezervacija
app.post('/api/auth/rezervacije', authMiddleWare, async (req, res) => {
    const { resurs_id, vrijeme_pocetka, vrijeme_zavrsetka } = req.body;
    const korisnik_id = req.user.id;

    if (!resurs_id || !vrijeme_pocetka || !vrijeme_zavrsetka) {
        return res.status(400).json({ greska: 'Sva polja (resurs_id, vrijeme_pocetka, vrijeme_zavrsetka) su obavezna.' });
    }

    // Validacija - Završetak > Početak i Početak >= Sada
    const start = new Date(vrijeme_pocetka);
    const end = new Date(vrijeme_zavrsetka);
    const now = new Date();

    if (end <= start) {
        return res.status(400).json({ greska: 'Vrijeme završetka mora biti nakon vremena početka.' });
    }
    if (start < now) {
        return res.status(400).json({ greska: 'Nije moguće kreirati rezervaciju u prošlosti.' });
    }

    // Validacija - Trajanje <= 8 sati
    const OSAM_SATI_MS = 8 * 60 * 60 * 1000;
    if (end.getTime() - start.getTime() > OSAM_SATI_MS) {
        return res.status(400).json({ greska: 'Rezervacija ne smije trajati dulje od 8 sati.' });
    }

    try {
        const [resursInfo] = await db.query('SELECT tip FROM Resursi WHERE id = ?', [resurs_id]);

        if (resursInfo.length === 0) {
            return res.status(404).json({ greska: 'Traženi resurs ne postoji u bazi.' });
        }
        const tip_resursa = resursInfo[0].tip;

        // Validacija - Zabrana pristupa
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

        // Validacija - Ponovljeno rezerviranje unutar 24h
        const DVADESETCETIRI_SATA_MS = 24 * 60 * 60 * 1000;
        const startMinus24h = new Date(start.getTime() - DVADESETCETIRI_SATA_MS);
        const endPlus24h = new Date(end.getTime() + DVADESETCETIRI_SATA_MS);

        const sqlProvjera24h = `
            SELECT id FROM Rezervacije 
            WHERE korisnik_id = ? 
              AND resurs_id = ? 
              AND status = 'aktivna'
              AND vrijeme_pocetka < ? 
              AND vrijeme_zavrsetka > ?
        `;
        const [preklapanja24h] = await db.query(sqlProvjera24h, [korisnik_id, resurs_id, endPlus24h, startMinus24h]);

        if (preklapanja24h.length > 0) {
            return res.status(429).json({
                greska: 'Već imate rezervaciju za ovaj resurs unutar 24 sata (prije ili poslije odabranog termina).'
            });
        }

        // Validacija - Double-booking
        const sqlProvjeraPreklapanja = `
            SELECT id FROM Rezervacije 
            WHERE resurs_id = ? 
              AND status = 'aktivna'
              AND vrijeme_pocetka < ? 
              AND vrijeme_zavrsetka > ?
        `;
        const [preklapanja] = await db.query(sqlProvjeraPreklapanja, [resurs_id, vrijeme_zavrsetka, vrijeme_pocetka]);

        if (preklapanja.length > 0) {
            return res.status(409).json({
                greska: 'Termin je zauzet. Odabrani resurs je već rezerviran u navedenom vremenu.'
            });
        }

        // Izvršavanje - Sve validacije uspješne, CREATE rezervacije
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

// RUTA - User [READ] rezervacije
app.get('/api/auth/korisnik/moje-rezervacije', authMiddleWare, async (req, res) => {
    const korisnik_id = req.user.id;

    try {
        const upit = `
            SELECT Rezervacije.*, Resursi.naziv AS naziv_resursa 
            FROM Rezervacije 
            JOIN Resursi ON Rezervacije.resurs_id = Resursi.id 
            WHERE Rezervacije.korisnik_id = ? 
            ORDER BY Rezervacije.id DESC
        `;

        const [mojeRezervacije] = await db.query(upit, [korisnik_id]);

        res.status(200).json(mojeRezervacije);
    } catch (error) {
        res.status(500).json({
            greska: 'Greška prilikom dohvaćanja vaših rezervacija.',
            detalji: error.message
        });
    }
});

// RUTA - User [UPDATE] - rezervacija
app.put('/api/auth/rezervacije/:id', authMiddleWare, async (req, res) => {
    const { id } = req.params;
    const { vrijeme_pocetka, vrijeme_zavrsetka, status } = req.body;
    const korisnik_id = req.user.id;

    if (!vrijeme_pocetka || !vrijeme_zavrsetka || !status) {
        return res.status(400).json({ greska: 'Sva polja (vrijeme_pocetka, vrijeme_zavrsetka, status) su obavezna.' });
    }

    // Validacija - Završetak > Početak i Početak >= Sada
    const start = new Date(vrijeme_pocetka);
    const end = new Date(vrijeme_zavrsetka);
    const now = new Date();

    if (end <= start) {
        return res.status(400).json({ greska: 'Vrijeme završetka mora biti nakon vremena početka.' });
    }
    if (start < now) {
        return res.status(400).json({ greska: 'Ne možete premjestiti rezervaciju u termin koji je već prošao.' });
    }

    // Validacija - Trajanje <= 8 sati
    const OSAM_SATI_MS = 8 * 60 * 60 * 1000;
    if (end.getTime() - start.getTime() > OSAM_SATI_MS) {
        return res.status(400).json({ greska: 'Rezervacija ne smije trajati dulje od 8 sati.' });
    }

    try {
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

        // Validacija - Zabrana pristupa
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

        if (status === 'aktivna') {
            // Validacija - Ponovljeno rezerviranje unutar 24h, ignorira samu sebe
            const DVADESETCETIRI_SATA_MS = 24 * 60 * 60 * 1000;
            const startMinus24h = new Date(start.getTime() - DVADESETCETIRI_SATA_MS);
            const endPlus24h = new Date(end.getTime() + DVADESETCETIRI_SATA_MS);

            const sqlProvjera24h = `
                SELECT id FROM Rezervacije 
                WHERE korisnik_id = ? 
                  AND resurs_id = ? 
                  AND status = 'aktivna'
                  AND id != ?
                  AND vrijeme_pocetka < ? 
                  AND vrijeme_zavrsetka > ?
            `;
            const [preklapanja24h] = await db.query(sqlProvjera24h, [korisnik_id, resurs_id, id, endPlus24h, startMinus24h]);

            if (preklapanja24h.length > 0) {
                return res.status(429).json({
                    greska: 'Već imate aktivnu rezervaciju za ovaj resurs unutar 24 sata (prije ili poslije odabranog termina).'
                });
            }

            // Validacija - Double-booking
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
                return res.status(409).json({
                    greska: 'Termin je zauzet. Odabrani resurs je već rezerviran u navedenom vremenu.'
                });
            }
        }

        // Izvršavanje - Sve validacije uspješne, UPDATE rezervacije
        await db.query(
            'UPDATE Rezervacije SET vrijeme_pocetka = ?, vrijeme_zavrsetka = ?, status = ? WHERE id = ? AND korisnik_id = ?',
            [vrijeme_pocetka, vrijeme_zavrsetka, status, id, korisnik_id]
        );

        res.status(200).json({ poruka: 'Rezervacija uspješno ažurirana!' });

    } catch (error) {
        res.status(500).json({ greska: 'Greška prilikom ažuriranja rezervacije.', detalji: error.message });
    }
});

// RUTA - User [READ] - zabrane
app.get('/api/auth/korisnik/moje-zabrane', authMiddleWare, async (req, res) => {
    const korisnik_id = req.user.id;

    try {
        const upit = `
            SELECT Zabrane_Pristupa.*, Resursi.naziv AS naziv_resursa 
            FROM Zabrane_Pristupa 
            LEFT JOIN Resursi ON Zabrane_Pristupa.resurs_id = Resursi.id 
            WHERE Zabrane_Pristupa.korisnik_id = ? 
            ORDER BY Zabrane_Pristupa.id DESC
        `;

        const [mojeZabrane] = await db.query(upit, [korisnik_id]);

        res.status(200).json(mojeZabrane);
    } catch (error) {
        res.status(500).json({
            greska: 'Greška prilikom dohvaćanja vaših zabrana pristupa.',
            detalji: error.message
        });
    }
});

// RUTA - User [READ] - resursi bez zabrane
app.get('/api/auth/resursi-dostupni', authMiddleWare, async (req, res) => {
    const korisnik_id = req.user.id;

    try {

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

// RUTA - User [READ] - zauzetost resursa
app.get('/api/auth/resursi/:id/zauzetost', authMiddleWare, async (req, res) => {
    const { id } = req.params;

    try {
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

// RUTA - Admin [READ] - korisnici
app.get('/api/korisnici', adminMiddleware, async (req, res) => {
    try {       
    const [rows] = await db.query('SELECT * FROM Korisnici');        
    res.status(200).json(rows);
} catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri dohvaćanju korisnika' }); }
});

// RUTA - Admin [CREATE] - korisnik
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

// RUTA - Admin [UPDATE] - korisnik
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

// RUTA - Admin [DELETE] - korisnik
app.delete('/api/korisnici/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    try {      
    await db.query('DELETE FROM Korisnici WHERE id = ?', [id]);
    res.status(200).json({ poruka: 'Korisnik uspješno obrisan' });
} catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri brisanju korisnika. Provjerite vanjske ključeve.' }); }
});

// RUTA - Admin [READ] - administratori
app.get('/api/administratori', adminMiddleware, async (req, res) => {
    try {
    const [rows] = await db.query('SELECT * FROM Administratori');
    res.status(200).json(rows);
} catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri dohvaćanju administratora' }); }
});

// RUTA - Admin [CREATE] - administrator
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

// RUTA - Admin [UPDATE] - administrator
app.put('/api/administratori/:id', adminMiddleware, async (req, res) => {
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

// RUTA - Admin [DELETE] - administrator
app.delete('/api/administratori/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        await db.query('DELETE FROM Administratori WHERE id = ?', [id]);
        res.status(200).json({ poruka: 'Administrator uspješno obrisan' });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri brisanju administratora' }); }
});

// RUTA - Admin [READ] - resursi
app.get('/api/resursi', adminMiddleware, async (req, res) => {
    try {
    const [rows] = await db.query('SELECT * FROM Resursi');
    res.status(200).json(rows);
} catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri dohvaćanju resursa' }); }
});

// RUTA - Admin [CREATE] - resurs
app.post('/api/resursi', adminMiddleware, async (req, res) => {
    const { naziv, tip, opis, kapacitet, status } = req.body;
    try {
        const [result] = await db.query('INSERT INTO Resursi (naziv, tip, opis, kapacitet, status) VALUES (?, ?, ?, ?, ?)', [naziv, tip, opis, kapacitet, status]);
        res.status(201).json({ poruka: 'Resurs uspješno kreiran', id: result.insertId });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri kreiranju resursa' }); }
});

// RUTA - Admin [UPDATE] - resurs
app.put('/api/resursi/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    const { naziv, tip, opis, kapacitet, status } = req.body;
    try {
        await db.query('UPDATE Resursi SET naziv = ?, tip = ?, opis = ?, kapacitet = ?, status = ? WHERE id = ?', [naziv, tip, opis, kapacitet, status, id]);
        res.status(200).json({ poruka: 'Resurs uspješno ažuriran' });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri ažuriranju resursa' }); }
});

// RUTA - Admin [DELETE] - resurs
app.delete('/api/resursi/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        await db.query('DELETE FROM Resursi WHERE id = ?', [id]);
        res.status(200).json({ poruka: 'Resurs uspješno obrisan' });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri brisanju resursa. Provjerite postoje li povezane rezervacije.' }); }
});

// RUTA - Admin [READ] - zabrane
app.get('/api/zabrane', adminMiddleware, async (req, res) => {
    try {
    const [rows] = await db.query('SELECT * FROM Zabrane_Pristupa');
    res.status(200).json(rows);
} catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri dohvaćanju zabrana' }); }
});

// RUTA - Admin [CREATE] - zabrana
app.post('/api/zabrane', adminMiddleware, async (req, res) => {
    const administrator_id = req.user.id;

    const { korisnik_id, resurs_id, tip_resursa, razlog, aktivna } = req.body;

    // Validacija - XOR za resurs_id i tip_resursa
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

    const administrator_id = req.user.id;

    const { korisnik_id, resurs_id, tip_resursa, razlog, aktivna } = req.body;

    // Validacija - XOR za resurs_id i tip_resursa
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

// RUTA - Admin [DELETE] - zabrana
app.delete('/api/zabrane/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        await db.query('DELETE FROM Zabrane_Pristupa WHERE id = ?', [id]);
        res.status(200).json({ poruka: 'Zabrana uspješno obrisana iz baze' });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri brisanju zabrane' }); }
});

// RUTA - Admin [READ] - rezervacije
app.get('/api/rezervacije', adminMiddleware, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM Rezervacije');
        res.status(200).json(rows);
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri dohvaćanju rezervacija' }); }
});

// RUTA - Admin [CREATE] - rezervacija
app.post('/api/rezervacije', adminMiddleware, async (req, res) => {
    const { korisnik_id, resurs_id, vrijeme_pocetka, vrijeme_zavrsetka, status, napomena_admina } = req.body;

    if (!korisnik_id || !resurs_id || !vrijeme_pocetka || !vrijeme_zavrsetka) {
        return res.status(400).json({ greska: 'Sva osnovna polja (korisnik_id, resurs_id, vrijeme_pocetka, vrijeme_zavrsetka) su obavezna.' });
    }

    // Validacija - Završetak > Početak i Početak >= Sada
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

        // Validacija - Zabrana pristupa
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

        // Validacija - Double-booking
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

        // Izvršavanje - Sve validacije uspješne, CREATE rezervacije
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

// RUTA - Admin [UPDATE] - rezervacija
app.put('/api/rezervacije/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    const { korisnik_id, resurs_id, vrijeme_pocetka, vrijeme_zavrsetka, status, napomena_admina } = req.body;

    if (!korisnik_id || !resurs_id || !vrijeme_pocetka || !vrijeme_zavrsetka || !status) {
        return res.status(400).json({ greska: 'Nedostaju obavezni podaci za ažuriranje.' });
    }

    // Validacija - Završetak > Početak i Početak >= Sada
    const start = new Date(vrijeme_pocetka);
    const end = new Date(vrijeme_zavrsetka);
    const now = new Date();

    if (end <= start) {
        return res.status(400).json({ greska: 'Vrijeme završetka mora biti nakon vremena početka.' });
    }

    if (start < now) {
        return res.status(400).json({ greska: 'Ne možete premjestiti rezervaciju u termin koji je već prošao.' });
    }

    try {
        const [resursInfo] = await db.query('SELECT tip FROM Resursi WHERE id = ?', [resurs_id]);

        if (resursInfo.length === 0) {
            return res.status(404).json({ greska: 'Traženi resurs ne postoji u bazi.' });
        }

        const tip_resursa = resursInfo[0].tip;

        // Validacija - Zabrana pristupa
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

        // Validacija - Double-booking
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

        // Izvršavanje - Sve validacije uspješne, UPDATE rezervacije
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

// RUTA - Admin [DELETE] - rezervacija
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