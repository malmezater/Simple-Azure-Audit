# 🔍 Azure Audit Checker

Ett heltäckande PowerShell-skript som granskar en Azure-prenumeration ur fem perspektiv – **Säkerhet**, **Kostnad**, **Infrastruktur**, **Compliance** och **Azure Advisor** – och genererar en snygg, färgkodad HTML-rapport tillsammans med en CSV-fil för vidare analys i Excel.

---

## ✨ Funktioner

Skriptet utför följande kontroller:

### 1. 🔐 Säkerhet
- **NSG-regler** – upptäcker farliga inbound-regler som öppnar känsliga portar (RDP `3389`, SSH `22`, SQL `1433`, MySQL `3306`, PostgreSQL `5432`, Telnet `23`, FTP `21`, SMB `445`, WinRM `5985/5986`) mot Internet (`0.0.0.0/0`).
- **Public IP-adresser** – hittar oassocierade Public IPs som ökar attackytan och kostnaderna.
- **RBAC** – varnar om fler än 3 Owner-roller finns på prenumerationsnivå.
- **Klassiska administratörer** – flaggar deprecerade legacy-roller (CoAdministrator / ServiceAdministrator).

### 2. 💰 Kostnad & oanvända resurser
- **Ohängda managed disks** – diskar som inte är kopplade till någon VM men ändå kostar.
- **Stoppade/deallocated VMs** – maskiner vars lagring fortfarande debiteras.
- **Lösa NIC:ar** – nätverksgränssnitt utan tillhörande VM.
- **Tomma resursgrupper** – RG:er helt utan resurser.

### 3. 🏗️ Infrastrukturhälsa
- **VM-diskkryptering** – kontrollerar att OS-diskar är krypterade (Azure Disk Encryption).
- **Key Vault-certifikat** – varnar för certifikat som löper ut inom 90 dagar (Critical ≤14 dagar, High ≤30 dagar, Medium ≤90 dagar).
- **Storage soft-delete** – kontrollerar att blob soft-delete är aktiverat.

### 4. ✅ Compliance & policy
- **Storage Accounts** – `Secure transfer required` (HTTPS only), lägsta TLS-version (≥1.2) samt publik blobåtkomst.
- **App Services** – HTTPS Only och lägsta TLS-version.
- **Key Vault** – Soft Delete och Purge Protection.
- **Taggning** – kontrollerar att obligatoriska taggar finns på alla resurser.

### 5. 📈 Azure Advisor
- Hämtar samtliga aktiva Azure Advisor-rekommendationer (kräver modulen `Az.Advisor`).

---

## 📋 Förutsättningar

| Krav | Detalj |
|------|--------|
| **PowerShell** | Version 7.0 eller senare |
| **Az-moduler** | `Az.Accounts`, `Az.Compute`, `Az.Network`, `Az.Storage`, `Az.KeyVault`, `Az.Resources`, `Az.Websites` |
| **Valfri modul** | `Az.Advisor` (krävs endast för Advisor-kontrollen) |
| **Behörighet** | Minst **Reader** på prenumerationsnivå. **Security Reader** rekommenderas för fullständiga säkerhetskontroller. |

### Installera nödvändiga moduler

```powershell
Install-Module Az.Accounts, Az.Compute, Az.Network, Az.Storage, Az.KeyVault, Az.Resources, Az.Websites -Scope CurrentUser

# Valfritt – för Azure Advisor-kontrollen
Install-Module Az.Advisor -Scope CurrentUser
```

---

## 🚀 Användning

```powershell
.\Invoke-AzureAudit.ps1 [-SubscriptionId <string>] [-OutputPath <string>] [-RequiredTags <string>] [-SkipAdvisor] [-OpenReport]
```

Om du inte redan är inloggad mot Azure öppnar skriptet automatiskt `Connect-AzAccount`.

### Parametrar

| Parameter | Typ | Standard | Beskrivning |
|-----------|-----|----------|-------------|
| `-SubscriptionId` | `string` | Aktiv kontext | Prenumerations-ID att köra mot. Utelämnas = den aktiva kontexten används. |
| `-OutputPath` | `string` | `.` (aktuell katalog) | Mapp där HTML-rapport och CSV sparas. Skapas automatiskt om den inte finns. |
| `-RequiredTags` | `string` | `"Environment,Owner,CostCenter"` | Kommaseparerad lista med obligatoriska taggar att kontrollera. |
| `-SkipAdvisor` | `switch` | Av | Hoppar över hämtning av Azure Advisor (snabbare körning). |
| `-OpenReport` | `switch` | Av | Öppnar HTML-rapporten automatiskt i webbläsaren efter körning. |

### Exempel

**Kör mot en specifik prenumeration och spara rapporten i en angiven mapp:**

```powershell
.\Invoke-AzureAudit.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -OutputPath "C:\AuditReports"
```

**Kör med egna obligatoriska taggar, hoppa över Advisor och öppna rapporten direkt:**

```powershell
.\Invoke-AzureAudit.ps1 -RequiredTags "Environment,Owner,Project" -SkipAdvisor -OpenReport
```

**Kör mot den aktiva kontexten med standardinställningar:**

```powershell
.\Invoke-AzureAudit.ps1
```

---

## 📊 Utdata

Vid varje körning genereras två filer i `-OutputPath`, namngivna efter prenumeration och tidsstämpel:

| Fil | Beskrivning |
|-----|-------------|
| `AzureAudit_<Prenumeration>_<tidsstämpel>.html` | Interaktiv, färgkodad rapport med översiktskort, fördelning per allvarlighet, fynd per kategori och en komplett tabell sorterad efter allvarlighet. Utskriftsvänlig. |
| `AzureAudit_<Prenumeration>_<tidsstämpel>.csv` | Semikolonseparerad CSV (UTF-8) med samtliga fynd för vidare analys i Excel. |

### Allvarlighetsnivåer

Varje fynd klassificeras med en av följande nivåer:

| Nivå | Färg | Betydelse |
|------|------|-----------|
| 🔴 **Critical** | Röd | Kräver omedelbar åtgärd (t.ex. RDP/SSH öppet mot Internet). |
| 🟠 **High** | Orange | Hög risk som bör åtgärdas snarast. |
| 🟡 **Medium** | Gul | Bör åtgärdas men inte akut. |
| 🟢 **Low** | Grön | Mindre förbättringar / städning. |
| 🔵 **Info** | Blå | Informativa fynd utan direkt risk. |

### Rapportens kolumner

| Kolumn | Innehåll |
|--------|----------|
| Kategori | Säkerhet, Kostnad, Infrastruktur, Compliance eller Advisor |
| Allvarlighet | Critical / High / Medium / Low / Info |
| Resurstyp | Typ av resurs som fyndet gäller |
| Resurs | Namn på den berörda resursen |
| Fynd | Beskrivning av det identifierade problemet |
| Rekommendation | Föreslagen åtgärd |
| Tidsstämpel | När fyndet registrerades |

---

## 💡 Tips

- Kör skriptet regelbundet (t.ex. via en schemalagd uppgift eller pipeline) för att följa miljöns hälsa över tid.
- Använd CSV-filen för att bygga trender och dashboards i Excel eller Power BI.
- Eftersom `$ErrorActionPreference` är satt till `SilentlyContinue` avbryts inte körningen om enstaka resurser saknar behörighet – kör med tillräckliga rättigheter för ett komplett resultat.

---

## ⚠️ Ansvarsfriskrivning

Skriptet utför **endast läsoperationer** och gör inga ändringar i din Azure-miljö. Rekommendationerna är generella riktlinjer – utvärdera alltid varje fynd utifrån din organisations behov och policyer innan du vidtar åtgärder.
