-- ريادة الغراء: schema v1
-- Run this migration in Supabase SQL Editor. Review the security notes below first.

create extension if not exists pgcrypto;

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table if not exists public.riyada_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  role text not null default 'activity_leader'
    check (role in ('school_admin','activity_leader','viewer')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.riyada_activities (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  activity_type text not null default 'برنامج',
  field text not null default '',
  description text not null default '',
  general_objective text not null default '',
  detailed_objectives text[] not null default '{}',
  target_group text not null default 'طلاب المدرسة',
  beneficiary_count integer not null default 0 check (beneficiary_count >= 0),
  start_date date,
  end_date date,
  status text not null default 'draft' check (status in ('draft','planned','in_progress','completed','archived')),
  location text not null default '',
  owner_name text not null default '',
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.riyada_evidence (
  id uuid primary key default gen_random_uuid(),
  activity_id uuid not null references public.riyada_activities(id) on delete cascade,
  storage_path text not null,
  caption text not null default '',
  uploaded_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now()
);

create table if not exists public.riyada_surveys (
  id uuid primary key default gen_random_uuid(),
  activity_id uuid references public.riyada_activities(id) on delete cascade,
  title text not null,
  purpose text not null default 'قياس الأثر',
  questions jsonb not null default '[]'::jsonb,
  is_published boolean not null default false,
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.riyada_survey_responses (
  id uuid primary key default gen_random_uuid(),
  survey_id uuid not null references public.riyada_surveys(id) on delete cascade,
  respondent_name text not null default '',
  answers jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.riyada_partnerships (
  id uuid primary key default gen_random_uuid(),
  activity_id uuid references public.riyada_activities(id) on delete set null,
  partner_name text not null,
  partnership_type text not null default '',
  contribution text not null default '',
  start_date date,
  end_date date,
  notes text not null default '',
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.riyada_assignments (
  id uuid primary key default gen_random_uuid(),
  activity_id uuid not null references public.riyada_activities(id) on delete cascade,
  assignee_name text not null,
  task_title text not null,
  assigned_date date not null default current_date,
  due_date date,
  notes text not null default '',
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now()
);

create or replace function private.riyada_current_role()
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select p.role
  from public.riyada_profiles p
  where p.user_id = (select auth.uid())
  limit 1;
$$;

create or replace function private.riyada_is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(private.riyada_current_role() = 'school_admin', false);
$$;

create or replace function public.riyada_touch_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

-- New Auth users get a non-admin profile. Promotion to school_admin must be done
-- by a trusted administrator from the Supabase SQL editor; never via client form.
create or replace function private.riyada_create_profile()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.riyada_profiles (user_id, full_name, role)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'full_name', ''),
    'activity_leader'
  )
  on conflict (user_id) do nothing;
  return new;
end;
$$;

drop trigger if exists riyada_auth_user_profile on auth.users;
create trigger riyada_auth_user_profile
after insert on auth.users
for each row execute function private.riyada_create_profile();

drop trigger if exists riyada_activities_updated_at on public.riyada_activities;
create trigger riyada_activities_updated_at before update on public.riyada_activities
for each row execute function public.riyada_touch_updated_at();
drop trigger if exists riyada_profiles_updated_at on public.riyada_profiles;
create trigger riyada_profiles_updated_at before update on public.riyada_profiles
for each row execute function public.riyada_touch_updated_at();
drop trigger if exists riyada_surveys_updated_at on public.riyada_surveys;
create trigger riyada_surveys_updated_at before update on public.riyada_surveys
for each row execute function public.riyada_touch_updated_at();
drop trigger if exists riyada_partnerships_updated_at on public.riyada_partnerships;
create trigger riyada_partnerships_updated_at before update on public.riyada_partnerships
for each row execute function public.riyada_touch_updated_at();

-- RLS on every exposed table and least-privilege grants.
alter table public.riyada_profiles enable row level security;
alter table public.riyada_activities enable row level security;
alter table public.riyada_evidence enable row level security;
alter table public.riyada_surveys enable row level security;
alter table public.riyada_survey_responses enable row level security;
alter table public.riyada_partnerships enable row level security;
alter table public.riyada_assignments enable row level security;

revoke all on public.riyada_profiles, public.riyada_activities, public.riyada_evidence,
  public.riyada_surveys, public.riyada_survey_responses, public.riyada_partnerships,
  public.riyada_assignments from anon, authenticated;
grant select, update on public.riyada_profiles to authenticated;
grant select, insert, update, delete on public.riyada_activities to authenticated;
grant select, insert, update, delete on public.riyada_evidence to authenticated;
grant select, insert, update, delete on public.riyada_surveys to authenticated;
grant select, insert on public.riyada_survey_responses to authenticated;
grant select, insert, update, delete on public.riyada_partnerships to authenticated;
grant select, insert, update, delete on public.riyada_assignments to authenticated;

-- Profiles: users can read their own profile; admins can read all. Users cannot change role.
drop policy if exists riyada_profiles_read on public.riyada_profiles;
create policy riyada_profiles_read on public.riyada_profiles
for select to authenticated
using (user_id = (select auth.uid()) or (select private.riyada_is_admin()));

drop policy if exists riyada_profiles_update_self on public.riyada_profiles;
create policy riyada_profiles_update_self on public.riyada_profiles
for update to authenticated
using (user_id = (select auth.uid()))
with check (user_id = (select auth.uid()) and role = (select private.riyada_current_role()));

-- Activities: leaders manage their own; admins manage all.
drop policy if exists riyada_activities_read on public.riyada_activities;
create policy riyada_activities_read on public.riyada_activities
for select to authenticated
using (created_by = (select auth.uid()) or (select private.riyada_is_admin()));
drop policy if exists riyada_activities_insert on public.riyada_activities;
create policy riyada_activities_insert on public.riyada_activities
for insert to authenticated
with check (created_by = (select auth.uid()) and (select private.riyada_current_role()) in ('activity_leader','school_admin'));
drop policy if exists riyada_activities_update on public.riyada_activities;
create policy riyada_activities_update on public.riyada_activities
for update to authenticated
using (created_by = (select auth.uid()) or (select private.riyada_is_admin()))
with check (created_by = (select auth.uid()) or (select private.riyada_is_admin()));
drop policy if exists riyada_activities_delete on public.riyada_activities;
create policy riyada_activities_delete on public.riyada_activities
for delete to authenticated
using (created_by = (select auth.uid()) or (select private.riyada_is_admin()));

-- Related records are allowed only when their parent activity is visible to the user.
drop policy if exists riyada_evidence_read on public.riyada_evidence;
create policy riyada_evidence_read on public.riyada_evidence for select to authenticated
using (exists (select 1 from public.riyada_activities a where a.id = activity_id and (a.created_by = (select auth.uid()) or (select private.riyada_is_admin()))));
drop policy if exists riyada_evidence_insert on public.riyada_evidence;
create policy riyada_evidence_insert on public.riyada_evidence for insert to authenticated
with check (uploaded_by = (select auth.uid()) and exists (select 1 from public.riyada_activities a where a.id = activity_id and (a.created_by = (select auth.uid()) or (select private.riyada_is_admin()))));
drop policy if exists riyada_evidence_update on public.riyada_evidence;
create policy riyada_evidence_update on public.riyada_evidence for update to authenticated
using (exists (select 1 from public.riyada_activities a where a.id = activity_id and (a.created_by = (select auth.uid()) or (select private.riyada_is_admin()))))
with check (uploaded_by = (select auth.uid()) and exists (select 1 from public.riyada_activities a where a.id = activity_id and (a.created_by = (select auth.uid()) or (select private.riyada_is_admin()))));
drop policy if exists riyada_evidence_delete on public.riyada_evidence;
create policy riyada_evidence_delete on public.riyada_evidence for delete to authenticated
using (exists (select 1 from public.riyada_activities a where a.id = activity_id and (a.created_by = (select auth.uid()) or (select private.riyada_is_admin()))));

drop policy if exists riyada_surveys_read on public.riyada_surveys;
create policy riyada_surveys_read on public.riyada_surveys for select to authenticated
using (created_by = (select auth.uid()) or (select private.riyada_is_admin()));
drop policy if exists riyada_surveys_insert on public.riyada_surveys;
create policy riyada_surveys_insert on public.riyada_surveys for insert to authenticated
with check (created_by = (select auth.uid()) and (select private.riyada_current_role()) in ('activity_leader','school_admin'));
drop policy if exists riyada_surveys_update on public.riyada_surveys;
create policy riyada_surveys_update on public.riyada_surveys for update to authenticated
using (created_by = (select auth.uid()) or (select private.riyada_is_admin()))
with check (created_by = (select auth.uid()) or (select private.riyada_is_admin()));
drop policy if exists riyada_surveys_delete on public.riyada_surveys;
create policy riyada_surveys_delete on public.riyada_surveys for delete to authenticated
using (created_by = (select auth.uid()) or (select private.riyada_is_admin()));

-- Survey responses: a respondent may submit to a published survey. Authenticated users can read responses only for surveys they own/administer.
drop policy if exists riyada_responses_read on public.riyada_survey_responses;
create policy riyada_responses_read on public.riyada_survey_responses for select to authenticated
using (exists (select 1 from public.riyada_surveys s where s.id = survey_id and (s.created_by = (select auth.uid()) or (select private.riyada_is_admin()))));
drop policy if exists riyada_responses_insert on public.riyada_survey_responses;
create policy riyada_responses_insert on public.riyada_survey_responses for insert to authenticated
with check (exists (select 1 from public.riyada_surveys s where s.id = survey_id and s.is_published = true));

drop policy if exists riyada_partnerships_read on public.riyada_partnerships;
create policy riyada_partnerships_read on public.riyada_partnerships for select to authenticated
using (created_by = (select auth.uid()) or (select private.riyada_is_admin()));
drop policy if exists riyada_partnerships_insert on public.riyada_partnerships;
create policy riyada_partnerships_insert on public.riyada_partnerships for insert to authenticated
with check (created_by = (select auth.uid()) and (select private.riyada_current_role()) in ('activity_leader','school_admin'));
drop policy if exists riyada_partnerships_update on public.riyada_partnerships;
create policy riyada_partnerships_update on public.riyada_partnerships for update to authenticated
using (created_by = (select auth.uid()) or (select private.riyada_is_admin()))
with check (created_by = (select auth.uid()) or (select private.riyada_is_admin()));
drop policy if exists riyada_partnerships_delete on public.riyada_partnerships;
create policy riyada_partnerships_delete on public.riyada_partnerships for delete to authenticated
using (created_by = (select auth.uid()) or (select private.riyada_is_admin()));

drop policy if exists riyada_assignments_read on public.riyada_assignments;
create policy riyada_assignments_read on public.riyada_assignments for select to authenticated
using (created_by = (select auth.uid()) or (select private.riyada_is_admin()));
drop policy if exists riyada_assignments_insert on public.riyada_assignments;
create policy riyada_assignments_insert on public.riyada_assignments for insert to authenticated
with check (created_by = (select auth.uid()) and (select private.riyada_current_role()) in ('activity_leader','school_admin'));
drop policy if exists riyada_assignments_update on public.riyada_assignments;
create policy riyada_assignments_update on public.riyada_assignments for update to authenticated
using (created_by = (select auth.uid()) or (select private.riyada_is_admin()))
with check (created_by = (select auth.uid()) or (select private.riyada_is_admin()));
drop policy if exists riyada_assignments_delete on public.riyada_assignments;
create policy riyada_assignments_delete on public.riyada_assignments for delete to authenticated
using (created_by = (select auth.uid()) or (select private.riyada_is_admin()));

-- Storage bucket for evidence files; uploads require authentication and ownership checks.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('riyada-evidence', 'riyada-evidence', false, 8388608, array['image/jpeg','image/png','image/webp','application/pdf'])
on conflict (id) do nothing;

drop policy if exists riyada_storage_read on storage.objects;
create policy riyada_storage_read on storage.objects for select to authenticated
using (bucket_id = 'riyada-evidence' and (storage.foldername(name))[1] = (select auth.uid())::text);
drop policy if exists riyada_storage_insert on storage.objects;
create policy riyada_storage_insert on storage.objects for insert to authenticated
with check (bucket_id = 'riyada-evidence' and (storage.foldername(name))[1] = (select auth.uid())::text);
drop policy if exists riyada_storage_delete on storage.objects;
create policy riyada_storage_delete on storage.objects for delete to authenticated
using (bucket_id = 'riyada-evidence' and (storage.foldername(name))[1] = (select auth.uid())::text);

-- Bootstrap an administrator after the first Auth user has been created:
-- update public.riyada_profiles set role = 'school_admin'
-- where user_id = (select id from auth.users where email = 'YOUR_ADMIN_EMAIL');
