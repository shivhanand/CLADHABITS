-- CLADHABITS license store
-- Run this once in your Supabase SQL Editor.

create table if not exists public.cladhabits_licenses (
  id uuid primary key default gen_random_uuid(),
  license_key text not null unique,
  customer_email text,
  customer_id text,
  status text not null default 'active' check (status in ('active','revoked','expired')),
  expires_at timestamptz,
  activation_count integer not null default 0,
  max_activations integer not null default 1,
  created_at timestamptz not null default now()
);

create index if not exists cladhabits_licenses_license_key_idx
  on public.cladhabits_licenses (license_key);

alter table public.cladhabits_licenses enable row level security;

-- No browser/client policy is created intentionally.
-- CLADHABITS accesses this table only from the Vercel server function
-- using the Supabase server secret.
