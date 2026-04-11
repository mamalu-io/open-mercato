# Raport bezpieczeństwa — open-mercato
**Data:** 2026-04-11  
**Metoda:** Automatyczny skan wzorowany na podejściu CVE discovery z [mtlynch.io](https://mtlynch.io/claude-code-found-linux-vulnerability/) — 3 równoległe agenty skanujące auth, API routes, injection vectors.

---

## Luka #1 (HIGH): Brak unieważnienia sesji po resecie hasła przez admina

### Plik
`packages/core/src/modules/customer_accounts/api/admin/users/[id]/reset-password.ts:44`

### Opis
Gdy admin wysyła `POST /api/customer_accounts/admin/users/:id/reset-password`, hasło użytkownika zostaje zmienione, ale **aktywne sesje portalu NIE są unieważniane**. Aktywna sesja pozostaje ważna do naturalnego wygaśnięcia (TTL ~120 min).

### Dowód — niespójność z resztą kodu

| Operacja | Plik | Sesja unieważniona? |
|---|---|---|
| Self-service reset hasła | `api/password/reset-confirm.ts:41` | ✅ TAK |
| Admin usuwa usera | `api/admin/users/[id].ts:205` | ✅ TAK |
| Portal usuwa usera | `api/portal/users/[id].ts:49` | ✅ TAK |
| **Admin resetuje hasło** | **`api/admin/users/[id]/reset-password.ts:44`** | ❌ **NIE — BUG** |

### Scenariusz ataku
1. Atakujący kradnie sesję portalu klienta (stolen cookie/token)
2. Ofiara zgłasza incydent → admin resetuje hasło przez panel
3. **Sesja atakującego nadal działa** — może odczytywać dane, składać zamówienia, itd.
4. Sesja wygaśnie samoczynnie dopiero po ~120 min

### Czy atakujący może zmienić hasło z powrotem?

**NIE.** Endpoint `POST /api/customer_accounts/portal/password-change` (`api/portal/password-change.ts:37`) wymaga `currentPassword` (weryfikuje `verifyPassword`). Atakujący nie zna nowego hasła ustawionego przez admina — nie może go zmienić. Ale nadal może **korzystać z sesji** przez jej pozostały czas życia.

### Fix

```typescript
// packages/core/src/modules/customer_accounts/api/admin/users/[id]/reset-password.ts

// 1. Dodać import:
import { CustomerSessionService } from '@open-mercato/core/modules/customer_accounts/services/customerSessionService'

// 2. Po updatePassword (linia 44) dodać:
const customerSessionService = container.resolve('customerSessionService') as CustomerSessionService
await customerSessionService.revokeAllUserSessions(user.id)
```

---

## Luka #2 (MEDIUM): Brak filtra `tenantId` w `isCancellationRequested`

### Plik
`packages/core/src/modules/progress/lib/progressServiceImpl.ts:246-249`

### Opis
```typescript
async isCancellationRequested(jobId) {
  const job = await em.findOne(ProgressJob, { id: jobId })  // ← brak tenantId!
  return job?.cancelRequestedAt != null
}
```

Wszystkie inne metody w tym pliku filtrują przez `tenantId`. Ta jedna nie. Pozwala sprawdzić stan anulowania dowolnego joba z innego tenanta jeśli znane jest UUID.

### Praktyczny impact
Metoda nie jest bezpośrednio w API — wywoływana wewnętrznie z sync engine i cancel endpoint (gdzie context jest już tenant-scoped). Ryzyko to **information leakage** (czy job z innego tenanta jest anulowany) — nie zapis ani modyfikacja danych.

### Fix

```typescript
// progressService.ts — dodać opcjonalny param:
isCancellationRequested(jobId: string, tenantId?: string): Promise<boolean>

// progressServiceImpl.ts:
async isCancellationRequested(jobId, tenantId?) {
  const filter: Record<string, unknown> = { id: jobId }
  if (tenantId) filter.tenantId = tenantId
  const job = await em.findOne(ProgressJob, filter)
  return job?.cancelRequestedAt != null
}
```

Backward-compatible (opcjonalny parametr). Istniejące wywołania w `data_sync/` działają bez zmian.

---

## Co NIE zostało znalezione

Trzeci agent sprawdził injection vectors i misconfigs — brak command injection, path traversal, SQL injection, XSS, hardcoded secrets, prompt injection w AI assistant. Ogólna kondycja bezpieczeństwa bazy kodu jest dobra.

---

## Rekomendacja

Naprawić **Lukę #1** jako priorytet — jest to wyraźna niespójność (wszystkie podobne operacje poprawnie unieważniają sesje, tylko ta jedna nie), łatwa do zreprodukowania, i zamknięcie jej wymaga 2 linii kodu.
