-- CareBridge schema for Supabase/PostgreSQL. Run as one script in SQL Editor.
-- Hackathon MVP: use synthetic/test data only; production healthcare use requires a security and compliance review.
create extension if not exists pgcrypto;

create table if not exists public.hospitals (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(trim(name)) between 2 and 140),
  created_at timestamptz not null default now()
);

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null check (char_length(trim(full_name)) between 1 and 100),
  email text not null,
  role text not null check (role in ('patient','provider')),
  hospital_id uuid references public.hospitals(id) on delete set null,
  created_at timestamptz not null default now(),
  constraint provider_requires_hospital check (role <> 'provider' or hospital_id is not null)
);
create unique index if not exists profiles_email_lower_unique on public.profiles (lower(email));

create table if not exists public.health_records (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references public.profiles(id) on delete cascade,
  created_by uuid not null references public.profiles(id) on delete restrict,
  title text not null check (char_length(trim(title)) between 1 and 160),
  record_type text not null check (record_type in ('Lab result','Prescription','Diagnosis','Imaging','Discharge summary','Other')),
  summary text check (summary is null or char_length(summary) <= 500),
  encrypted_payload jsonb not null check (encrypted_payload ? 'algorithm' and encrypted_payload->>'algorithm' = 'AES-GCM'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint patient_is_creator check (patient_id = created_by)
);
create index if not exists health_records_patient_created_idx on public.health_records(patient_id, created_at desc);

create table if not exists public.consent_requests (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references public.profiles(id) on delete cascade,
  provider_id uuid not null references public.profiles(id) on delete cascade,
  hospital_id uuid references public.hospitals(id) on delete set null,
  purpose text not null check (purpose in ('Continuity of care','Specialist consultation','Emergency treatment','Second opinion','Diagnostic follow-up')),
  status text not null default 'pending' check (status in ('pending','active','denied','revoked','expired')),
  requested_at timestamptz not null default now(),
  decided_at timestamptz,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  check (patient_id <> provider_id),
  check (expires_at > requested_at)
);
create index if not exists consent_patient_status_idx on public.consent_requests(patient_id, status, created_at desc);
create index if not exists consent_provider_status_idx on public.consent_requests(provider_id, status, created_at desc);

create table if not exists public.access_logs (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references public.profiles(id) on delete cascade,
  actor_id uuid not null references public.profiles(id) on delete cascade,
  record_id uuid references public.health_records(id) on delete set null,
  consent_id uuid references public.consent_requests(id) on delete set null,
  action text not null check (action in ('record_access','record_decrypted','consent_requested','consent_granted','consent_denied','consent_revoked')),
  outcome text not null check (outcome in ('allowed','blocked')),
  details text check (details is null or char_length(details) <= 500),
  accessed_at timestamptz not null default now()
);
create index if not exists access_logs_patient_time_idx on public.access_logs(patient_id, accessed_at desc);
create index if not exists access_logs_actor_time_idx on public.access_logs(actor_id, accessed_at desc);

create or replace function public.set_updated_at() returns trigger language plpgsql set search_path = public as $$
begin new.updated_at = now(); return new; end; $$;
drop trigger if exists health_records_updated_at on public.health_records;
create trigger health_records_updated_at before update on public.health_records for each row execute function public.set_updated_at();

-- Create a profile from Auth metadata. The role is constrained and a provider gets a hospital row.
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public, auth as $$
declare v_role text; v_hospital_id uuid; v_name text; v_hospital_name text;
begin
  v_role := case when new.raw_user_meta_data->>'role' = 'provider' then 'provider' else 'patient' end;
  v_name := coalesce(nullif(trim(new.raw_user_meta_data->>'full_name'),''), split_part(new.email,'@',1));
  if v_role = 'provider' then
    v_hospital_name := coalesce(nullif(trim(new.raw_user_meta_data->>'hospital_name'),''), 'Unregistered clinic');
    insert into public.hospitals(name) values (v_hospital_name) returning id into v_hospital_id;
  end if;
  insert into public.profiles(id,full_name,email,role,hospital_id) values (new.id,left(v_name,100),lower(new.email),v_role,v_hospital_id);
  return new;
end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

alter table public.hospitals enable row level security;
alter table public.profiles enable row level security;
alter table public.health_records enable row level security;
alter table public.consent_requests enable row level security;
alter table public.access_logs enable row level security;

-- Least-privilege direct access: profiles are private; only your own profile is directly readable.
drop policy if exists profiles_select_own on public.profiles;
create policy profiles_select_own on public.profiles for select to authenticated using (id = auth.uid());
drop policy if exists profiles_update_own on public.profiles;
-- Profile role and hospital membership are immutable from the client; manage changes through reviewed admin tooling.
drop policy if exists hospitals_read_member on public.hospitals;
create policy hospitals_read_member on public.hospitals for select to authenticated using (id = (select p.hospital_id from public.profiles p where p.id = auth.uid()));

-- Patients can directly read and manage only their own encrypted records. Providers use the audited RPC below.
drop policy if exists records_select_owner on public.health_records;
create policy records_select_owner on public.health_records for select to authenticated using (patient_id = auth.uid());
drop policy if exists records_insert_owner on public.health_records;
create policy records_insert_owner on public.health_records for insert to authenticated with check (patient_id = auth.uid() and created_by = auth.uid() and (select p.role from public.profiles p where p.id = auth.uid()) = 'patient');
drop policy if exists records_delete_owner on public.health_records;
create policy records_delete_owner on public.health_records for delete to authenticated using (patient_id = auth.uid() and (select p.role from public.profiles p where p.id = auth.uid()) = 'patient');
drop policy if exists records_update_owner on public.health_records;
create policy records_update_owner on public.health_records for update to authenticated using (patient_id = auth.uid()) with check (patient_id = auth.uid() and created_by = auth.uid());

-- Consent metadata is visible only to the patient and the requesting provider. State changes are RPC-only.
drop policy if exists consent_select_participants on public.consent_requests;
create policy consent_select_participants on public.consent_requests for select to authenticated using (patient_id = auth.uid() or provider_id = auth.uid());
drop policy if exists consent_insert_provider on public.consent_requests;
create policy consent_insert_provider on public.consent_requests for insert to authenticated with check (provider_id = auth.uid() and status = 'pending' and hospital_id is not distinct from (select p.hospital_id from public.profiles p where p.id = auth.uid()) and (select p.role from public.profiles p where p.id = auth.uid()) = 'provider');
-- No direct UPDATE policy: approvals/revocations must go through trusted database functions.

drop policy if exists logs_select_participants on public.access_logs;
create policy logs_select_participants on public.access_logs for select to authenticated using (patient_id = auth.uid() or actor_id = auth.uid());
-- No direct INSERT/UPDATE/DELETE policy for audit logs.

create or replace function public.find_patient_by_email(p_email text)
returns table(id uuid, full_name text, email text) language plpgsql security definer set search_path = public, auth as $$
begin
  if auth.uid() is null or not exists(select 1 from public.profiles p where p.id=auth.uid() and p.role='provider') then raise exception 'Only authenticated providers can look up patients'; end if;
  return query select p.id,p.full_name,p.email from public.profiles p where lower(p.email)=lower(trim(p_email)) and p.role='patient' limit 1;
end; $$;

create or replace function public.approve_consent_request(p_consent_id uuid)
returns void language plpgsql security definer set search_path = public, auth as $$
declare c public.consent_requests%rowtype;
begin
  select * into c from public.consent_requests where id=p_consent_id for update;
  if not found or c.patient_id <> auth.uid() then raise exception 'Consent request not found or not owned by you'; end if;
  if c.status <> 'pending' then raise exception 'Only pending requests can be approved'; end if;
  if c.expires_at <= now() then update public.consent_requests set status='expired',decided_at=now() where id=c.id; raise exception 'This request has expired'; end if;
  update public.consent_requests set status='active',decided_at=now() where id=c.id;
  insert into public.access_logs(patient_id,actor_id,consent_id,action,outcome,details) values(c.patient_id,auth.uid(),c.id,'consent_granted','allowed','Patient approved provider access');
end; $$;

create or replace function public.deny_consent_request(p_consent_id uuid)
returns void language plpgsql security definer set search_path = public, auth as $$
declare c public.consent_requests%rowtype;
begin
  select * into c from public.consent_requests where id=p_consent_id for update;
  if not found or c.patient_id <> auth.uid() then raise exception 'Consent request not found or not owned by you'; end if;
  if c.status <> 'pending' then raise exception 'Only pending requests can be denied'; end if;
  update public.consent_requests set status='denied',decided_at=now() where id=c.id;
  insert into public.access_logs(patient_id,actor_id,consent_id,action,outcome,details) values(c.patient_id,auth.uid(),c.id,'consent_denied','allowed','Patient denied provider access');
end; $$;

create or replace function public.revoke_consent_grant(p_consent_id uuid)
returns void language plpgsql security definer set search_path = public, auth as $$
declare c public.consent_requests%rowtype;
begin
  select * into c from public.consent_requests where id=p_consent_id for update;
  if not found or c.patient_id <> auth.uid() then raise exception 'Consent grant not found or not owned by you'; end if;
  if c.status <> 'active' then raise exception 'Only active grants can be revoked'; end if;
  update public.consent_requests set status='revoked',decided_at=now() where id=c.id;
  insert into public.access_logs(patient_id,actor_id,consent_id,action,outcome,details) values(c.patient_id,auth.uid(),c.id,'consent_revoked','allowed','Patient revoked provider access');
end; $$;

-- Only this RPC exposes shared ciphertext to a provider, and every retrieval writes an audit event in the same transaction.
create or replace function public.get_shared_records(p_consent_id uuid)
returns table(id uuid,patient_id uuid,title text,record_type text,summary text,encrypted_payload jsonb,created_at timestamptz)
language plpgsql security definer set search_path = public, auth as $$
declare c public.consent_requests%rowtype; rec public.health_records%rowtype;
begin
  select * into c from public.consent_requests where consent_requests.id=p_consent_id for share;
  if not found or c.provider_id <> auth.uid() or c.status <> 'active' or c.expires_at <= now() then raise exception 'No active consent grant for this request'; end if;
  for rec in select * from public.health_records r where r.patient_id=c.patient_id order by r.created_at desc loop
    insert into public.access_logs(patient_id,actor_id,record_id,consent_id,action,outcome,details) values(c.patient_id,auth.uid(),rec.id,c.id,'record_access','allowed','Provider retrieved encrypted record under active consent');
    id:=rec.id; patient_id:=rec.patient_id; title:=rec.title; record_type:=rec.record_type; summary:=rec.summary; encrypted_payload:=rec.encrypted_payload; created_at:=rec.created_at; return next;
  end loop;
end; $$;

create or replace function public.log_record_decryption(p_record_id uuid)
returns void language plpgsql security definer set search_path = public, auth as $$
declare r public.health_records%rowtype; c public.consent_requests%rowtype;
begin
  select * into r from public.health_records where id=p_record_id;
  if not found then raise exception 'Record not found'; end if;
  if r.patient_id = auth.uid() then
    insert into public.access_logs(patient_id,actor_id,record_id,action,outcome,details) values(r.patient_id,auth.uid(),r.id,'record_decrypted','allowed','Patient decrypted record locally');
    return;
  end if;
  select * into c from public.consent_requests where patient_id=r.patient_id and provider_id=auth.uid() and status='active' and expires_at>now() order by decided_at desc limit 1;
  if not found then raise exception 'No active consent for this record'; end if;
  insert into public.access_logs(patient_id,actor_id,record_id,consent_id,action,outcome,details) values(r.patient_id,auth.uid(),r.id,c.id,'record_decrypted','allowed','Provider decrypted shared record locally');
end; $$;

-- Record every newly submitted request as an audit event.
create or replace function public.audit_consent_request() returns trigger language plpgsql security definer set search_path=public as $$
begin insert into public.access_logs(patient_id,actor_id,consent_id,action,outcome,details) values(new.patient_id,new.provider_id,new.id,'consent_requested','allowed','Provider requested patient consent'); return new; end; $$;
drop trigger if exists consent_request_audit on public.consent_requests;
create trigger consent_request_audit after insert on public.consent_requests for each row execute function public.audit_consent_request();

revoke all on function public.find_patient_by_email(text) from public;
revoke all on function public.approve_consent_request(uuid) from public;
revoke all on function public.deny_consent_request(uuid) from public;
revoke all on function public.revoke_consent_grant(uuid) from public;
revoke all on function public.get_shared_records(uuid) from public;
revoke all on function public.log_record_decryption(uuid) from public;
grant execute on function public.find_patient_by_email(text) to authenticated;
grant execute on function public.approve_consent_request(uuid) to authenticated;
grant execute on function public.deny_consent_request(uuid) to authenticated;
grant execute on function public.revoke_consent_grant(uuid) to authenticated;
grant execute on function public.get_shared_records(uuid) to authenticated;
grant execute on function public.log_record_decryption(uuid) to authenticated;

-- Explicit table privileges; RLS above remains the enforcement boundary.
grant usage on schema public to authenticated;
grant select on public.hospitals, public.profiles, public.health_records, public.consent_requests, public.access_logs to authenticated;
grant insert, delete on public.health_records to authenticated;
grant insert on public.consent_requests to authenticated;


-- Secure audit feed with identity fields; only the patient or the actor in each event can see it.
create or replace function public.get_access_history()
returns table(id uuid,patient_id uuid,actor_id uuid,actor_name text,actor_email text,record_id uuid,record_title text,action text,outcome text,accessed_at timestamptz,details text)
language plpgsql security definer set search_path = public, auth as $$
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  return query
    select l.id,l.patient_id,l.actor_id,p.full_name,p.email,l.record_id,r.title,l.action,l.outcome,l.accessed_at,l.details
    from public.access_logs l
    join public.profiles p on p.id=l.actor_id
    left join public.health_records r on r.id=l.record_id
    where l.patient_id=auth.uid() or l.actor_id=auth.uid()
    order by l.accessed_at desc limit 500;
end; $$;
revoke all on function public.get_access_history() from public;
grant execute on function public.get_access_history() to authenticated;
