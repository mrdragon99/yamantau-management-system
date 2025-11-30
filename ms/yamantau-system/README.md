# Cos - Yamantau Management System

Sistema di gestione membri Yamantau con interfaccia grafica, autenticazione e chat integrata.

## Caratteristiche

- 🔐 **Autenticazione sicura** con bcrypt
- 👥 **Gestione membri Yamantau** (CRUD completo)
- 💬 **Chat TCP integrata** con server multi-client
- 🎨 **Interfaccia moderna** con CustomTkinter (dark mode)
- 📊 **Dashboard con statistiche**
- 🔍 **Ricerca avanzata** con ranking
- 📝 **Logging completo** delle operazioni

## Requisiti

- Python 3.8+
- customtkinter
- bcrypt

## Installazione

```bash
# Clona o scarica il progetto
cd yamantau-system

# Installa le dipendenze
pip install -r requirements.txt
```

## Utilizzo

```bash
python cosz1_app.py
```

### Primo Accesso

1. Avvia l'applicazione
2. Clicca su "Register" per creare un nuovo account
3. Inserisci username e password (minimo 6 caratteri)
4. Effettua il login con le credenziali create

### Funzionalità Principali

#### Dashboard
- Visualizza statistiche sistema
- Numero totale Yamantau
- Stato sistema
- Membri recenti

#### Gestione Yamantau
- **Aggiungi**: Inserisci nuovi membri con tutti i dettagli
- **Visualizza**: Tabella completa con tutti i membri
- **Modifica**: Aggiorna informazioni esistenti
- **Elimina**: Rimuovi membri (con conferma)
- **Cerca**: Ricerca intelligente su tutti i campi

#### Chat
- Chat in tempo reale tra utenti connessi
- Server TCP integrato
- Messaggi con timestamp
- Indicatore stato connessione

## Struttura Dati

### Utente
- Username
- Password (hash bcrypt)

### Yamantau
- First Name
- Last Name
- Nickname (Username)
- Yamantau Code (univoco)
- Birth Date (YYYY-MM-DD)
- Registration Date (automatica)

## File Generati

- `users.json` - Database utenti
- `yamantau_<username>.json` - Database membri per utente
- `yamantau_system.log` - Log applicazione

## Configurazione

Modifica il dizionario `CONFIG` in `cosz1_app.py`:

```python
CONFIG = {
    'chat_host': '127.0.0.1',      # Host server chat
    'chat_port': 5555,              # Porta server chat
    'db_type': 'json',              # Tipo database
    'min_password_length': 6        # Lunghezza minima password
}
```

## Miglioramenti Implementati

### Rispetto al Codice Originale

1. **Logging System**: Tracciamento completo delle operazioni
2. **Configurazione Centralizzata**: CONFIG dictionary
3. **Error Handling Migliorato**: Gestione errori più robusta
4. **Codice Ottimizzato**: Riduzione ridondanze
5. **Bug Fixes**:
   - Corretto `member_manager` → `yamantau_manager`
   - Migliorata gestione thread chat
   - Validazione input più robusta
   - Gestione corruzione file JSON

## Sicurezza

- Password hashate con bcrypt (salt automatico)
- Validazione input su tutti i form
- Gestione sicura delle connessioni socket
- Separazione dati per utente

## Troubleshooting

### La chat non si connette
- Verifica che la porta 5555 sia libera
- Controlla il firewall
- Verifica i log in `yamantau_system.log`

### File JSON corrotto
- L'applicazione ricrea automaticamente i file corrotti
- Backup manuale consigliato dei file `.json`

### Errore bcrypt
```bash
pip install --upgrade bcrypt
```

## Sviluppi Futuri

- [ ] Database SQLite
- [ ] Export/Import dati (CSV, Excel)
- [ ] Grafici statistiche
- [ ] Notifiche sistema
- [ ] Backup automatico
- [ ] Multi-lingua
- [ ] Temi personalizzabili

## Licenza

Progetto personale - Uso libero ma con rispetto del autore

## Autore

yamantau Team - Central obliovion security

## Supporto

Per problemi o domande, controlla i log o apri una issue.
