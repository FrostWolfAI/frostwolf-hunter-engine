-- The detail a white-box finding carries: how the flaw works, where it lives, how
-- to fix it, and the specific code it was grounded in. Without these a finding is a
-- title and a severity; with them it is something an engineer can act on, which is
-- the whole point (HUNTER-PRD.md §7.6).
--
-- `location` is a comma-separated list of `path:line` references into the analysed
-- repository. `evidence` is the code the verdict was grounded in. Neither is a
-- secret — it is the customer's own source, which they connected for review.

ALTER TABLE hunter_findings ADD COLUMN mechanism TEXT;
ALTER TABLE hunter_findings ADD COLUMN location TEXT;
ALTER TABLE hunter_findings ADD COLUMN remediation TEXT;
ALTER TABLE hunter_findings ADD COLUMN evidence TEXT;
