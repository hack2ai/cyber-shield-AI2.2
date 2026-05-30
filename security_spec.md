# Security Specification for Phish Intel

## Data Invariants
1. **Users (/users/{userId})**:
   - Must be signed in to create/read their own profile.
   - `uid` must match `auth.uid`.
   - `role` cannot be changed by the user (only by server/admin).
2. **Scan Reports (/scanReports/{reportId})**:
   - `userId` must match `auth.uid`.
   - Users can only read their own reports.
   - Reports are immutable after creation.
   - `threatScore` must be between 0 and 100.

## The "Dirty Dozen" Payloads

1. **Identity Spoofing**: Create a report with someone else's `userId`.
2. **Role Escalation**: Update own user profile to set `role: 'admin'`.
3. **Cross-User Read**: Attempt to 'get' a `scanReport` belonging to another user.
4. **Anonymous Write**: Attempt to create a report without being signed in.
5. **Collection Scraping**: Attempt to 'list' all `scanReports` without a filter.
6. **Data Poisoning**: Inject a 2MB string into `target` field.
7. **Invalid Score**: Set `threatScore` to 999.
8. **Malicious ID**: Use a document ID that is 200KB long.
9. **Timestamp Manipulation**: Set `createdAt` to a future date instead of server time.
10. **Shadow Field Injection**: Create a report with an un-whitelisted field `isVerified: true`.
11. **Bypass Verification**: Write to Firestore using an unverified email (if verification required).
12. **Orphaned Write**: Create a report for a `userId` that doesn't exist in `/users`.

## The Test Runner (firestore.rules.test.ts)

```typescript
// Conceptual test cases
describe('Firestore Security Rules', () => {
  it('should deny cross-user report reads', async () => { ... });
  it('should prevent self-promotion to admin', async () => { ... });
  it('should enforce userId integrity on scan reports', async () => { ... });
});
```
