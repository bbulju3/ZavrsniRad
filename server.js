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

// Authorized [CREATE] - rezervacija

app.post('/api/auth/rezervacije', authMiddleWare, async (req, res) => {
    const { resurs_id, vrijeme_pocetka, vrijeme_zavrsetka } = req.body;

    // ID korisnika automatski izvlačimo iz JWT tokena (postavio ga je authMiddleware)
    const korisnik_id = req.user.id;

    if (!resurs_id || !vrijeme_pocetka || !vrijeme_zavrsetka) {
        return res.status(400).json({ greska: 'Sva polja (resurs_id, vrijeme_pocetka, vrijeme_zavrsetka) su obavezna.' });
    }

    try {
        // --- 1. VALIDACIJA: Provjera ima li korisnik aktivnu zabranu pristupa ---
        const [zabrane] = await db.query(
            'SELECT id, razlog FROM Zabrane_Pristupa WHERE korisnik_id = ? AND aktivna = true',
            [korisnik_id]
        );
        if (zabrane.length > 0) {
            return res.status(403).json({
                greska: 'Rezervacija odbijena. Imate aktivnu zabranu pristupa sustavu!',
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

// [READ] - korisnici
app.get('/api/korisnici', adminMiddleware, async (req, res) => {
    try {       
    const [rows] = await db.query('SELECT * FROM Korisnici');        
    res.status(200).json(rows);
} catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri dohvaćanju korisnika' }); }
});
// [CREATE] - korisnik
app.post('/api/korisnici', adminMiddleware, async (req, res) => {    
    const { ime, prezime, email, lozinka_hash } = req.body;
    try {       
        const [result] = await db.query('INSERT INTO Korisnici (ime, prezime, email, lozinka_hash) VALUES (?, ?, ?, ?)', [ime, prezime, email, lozinka_hash]);      
        res.status(201).json({ poruka: 'Korisnik uspješno kreiran', id: result.insertId });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri kreiranju korisnika' }); }
});
// [UPDATE] - korisnik
app.put('/api/korisnici/:id', adminMiddleware, async (req, res) => {    
    const { id } = req.params;
    const { ime, prezime, email, lozinka_hash } = req.body;
    try {      
        await db.query('UPDATE Korisnici SET ime = ?, prezime = ?, email = ?, lozinka_hash = ? WHERE id = ?', [ime, prezime, email, lozinka_hash, id]);
        res.status(200).json({ poruka: 'Korisnički podaci uspješno ažurirani' });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri ažuriranju korisnika' }); }
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
    const { ime, prezime, email, lozinka_hash } = req.body;
    try {
        const [result] = await db.query('INSERT INTO Administratori (ime, prezime, email, lozinka_hash) VALUES (?, ?, ?, ?)', [ime, prezime, email, lozinka_hash]);
        res.status(201).json({ poruka: 'Administrator uspješno kreiran', id: result.insertId });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri kreiranju administratora' }); }
});
// [UPDATE] - administrator
app.put('/api/administratori/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    const { ime, prezime, email, lozinka_hash } = req.body;
    try {
        await db.query('UPDATE Administratori SET ime = ?, prezime = ?, email = ?, lozinka_hash = ? WHERE id = ?', [ime, prezime, email, lozinka_hash, id]);
        res.status(200).json({ poruka: 'Administratorski podaci uspješno ažurirani' });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri ažuriranju administratora' }); }
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
    const { korisnik_id, administrator_id, resurs_id, tip_resursa, razlog, aktivna } = req.body;
    try {
        const [result] = await db.query('INSERT INTO Zabrane_Pristupa (korisnik_id, administrator_id, resurs_id, tip_resursa, razlog, aktivna) VALUES (?, ?, ?, ?, ?, ?)', [korisnik_id, administrator_id, resurs_id, tip_resursa, razlog, aktivna || true]);
        res.status(201).json({ poruka: 'Zabrana uspješno kreirana', id: result.insertId });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri kreiranju zabrane' }); }
});
// [UPDATE] - zabrana
app.put('/api/zabrane/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    const { korisnik_id, administrator_id, resurs_id, tip_resursa, razlog, aktivna } = req.body;
    try {
        await db.query('UPDATE Zabrane_Pristupa SET korisnik_id = ?, administrator_id = ?, resurs_id = ?, tip_resursa = ?, razlog = ?, aktivna = ? WHERE id = ?', [korisnik_id, administrator_id, resurs_id, tip_resursa, razlog, aktivna, id]);
        res.status(200).json({ poruka: 'Zabrana pristupa uspješno ažurirana' });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri ažuriranju zabrane' }); }
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
// [CREATE] - rezervacija
app.post('/api/rezervacije', adminMiddleware, async (req, res) => {
    const { korisnik_id, resurs_id, vrijeme_pocetka, vrijeme_zavrsetka, status, napomena_admina } = req.body;
    try {
        const [result] = await db.query('INSERT INTO Rezervacije (korisnik_id, resurs_id, vrijeme_pocetka, vrijeme_zavrsetka, status, napomena_admina) VALUES (?, ?, ?, ?, ?, ?)', [korisnik_id, resurs_id, vrijeme_pocetka, vrijeme_zavrsetka, status || 'aktivna', napomena_admina || null]);
        res.status(201).json({ poruka: 'Rezervacija uspješno kreirana', id: result.insertId });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri kreiranju rezervacije' }); }
});
// [UPDATE] - rezervacija
app.put('/api/rezervacije/:id', adminMiddleware, async (req, res) => {
    const { id } = req.params;
    const { korisnik_id, resurs_id, vrijeme_pocetka, vrijeme_zavrsetka, status, napomena_admina } = req.body;
    try {
        await db.query('UPDATE Rezervacije SET korisnik_id = ?, resurs_id = ?, vrijeme_pocetka = ?, vrijeme_zavrsetka = ?, status = ?, napomena_admina = ? WHERE id = ?', [korisnik_id, resurs_id, vrijeme_pocetka, vrijeme_zavrsetka, status, napomena_admina, id]);
        res.status(200).json({ poruka: 'Rezervacija uspješno izmijenjena' });
    } catch (error) { console.error(error); res.status(500).json({ greska: 'Greška pri izmjeni rezervacije' }); }
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