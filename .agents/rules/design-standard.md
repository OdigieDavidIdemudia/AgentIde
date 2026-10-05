---
trigger: always_on
---

# Project Design Standard

All UI and frontend work in this project MUST follow the design standards defined in the `design/` folder at the project root. Always read the relevant JSON files before generating any UI code, mockup, or layout.

## Key Design Files
- `design/standard.json` — Visual language standard (colors, typography, spacing, motion, style variants, accessibility)
- `design/admin-standard.json` — Admin panel functional standard (user management, data tables, empty states, navigation)
- `design/marketing-standard.json` — Marketing pages standard
- `design/deployment-standard.json` — Deployment layout standard

## Critical Rules (from standard.json)
1. **Style Variant**: For dashboards and security tools, use the `technicalMono` typography pairing (Space Grotesk headings, JetBrains Mono / Inter body) and the `neobrutalism` or `minimalism` style variant. Never use claymorphism for data-heavy tools.
2. **Color System**: Always implement BOTH light and dark modes. Dark mode is designed, not auto-inverted. Use the neutral scale (50–900). The accent color is a single project-specific color — never violet/indigo (explicitly banned).
3. **Spacing**: Always use the spacing scale tokens (xxs=4px, xs=8px, sm=12px, md=16px, lg=24px, xl=32px, 2xl=48px). Never hand-pick one-off pixel values.
4. **Accessibility**: Minimum contrast ratio 4.5:1 (text), 3:1 (large text). Minimum touch target 44px. Never convey meaning by color alone — always pair with text/icon.
5. **Motion**: Every animation must have a reason. Use defined durations (instant=80ms, fast=150ms, base=220ms, slow=400ms) and easing curves from the standard.

## Critical Admin UI Rules (from admin-standard.json)
1. **Empty States**: A table with zero rows MUST show a clear message and a primary action CTA — never render a bare header with dead space below.
2. **Data Tables**: Must have sticky column headers, row-level actions (inline or row menu), and search/filter for lists exceeding ~15 rows.
3. **Destructive Actions**: Always require an explicit confirmation dialog. Never a single click with no confirmation.
4. **User Management**: Any screen with roles or logins must include: create user, invite, edit, deactivate/reactivate, unlock, reset password, role assignment, last-login visibility, search/filter.
5. **Active Nav State**: Current section is visually distinguished using accent color — deliberately, not as a wash.

## Before Building Any UI
1. Read the relevant `design/*.json` file(s) for the component type.
2. Confirm the style variant and typography pairing chosen for the project.
3. Apply both `standard.json` AND `admin-standard.json` together for any admin/dashboard screen.
