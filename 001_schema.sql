-- 새 Supabase 프로젝트의 SQL Editor에서 한 번 실행하세요.
begin;
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;

create table public.members (
  user_id uuid primary key references auth.users(id),
  display_name text not null check(length(btrim(display_name)) between 1 and 80),
  active boolean not null default true
);
alter table public.members enable row level security;
revoke all on public.members from anon, authenticated;
grant select on public.members to authenticated;
create policy own_membership on public.members for select to authenticated
using(user_id=(select auth.uid()) and active);

create function private.is_member() returns boolean language sql stable security definer
set search_path = '' as $$
 select exists(select 1 from public.members where user_id=auth.uid() and active);
$$;
revoke all on function private.is_member() from public, anon;
grant execute on function private.is_member() to authenticated;

create table public.projects (
 id uuid primary key,
 data jsonb not null check(jsonb_typeof(data)='object'),
 created_on date not null default ((now() at time zone 'Asia/Seoul')::date),
 version integer not null default 1 check(version>0),
 archived boolean not null default false,
 import_key text unique,
 updated_at timestamptz not null default now(),
 updated_by uuid not null references auth.users(id)
);
create index projects_year_idx on public.projects ((data->>'year'));
alter table public.projects enable row level security;
revoke all on public.projects from anon,authenticated;
grant select on public.projects to authenticated;
create policy member_read on public.projects for select to authenticated using((select private.is_member()));

create table public.project_history (
 id bigint generated always as identity primary key,
 project_id uuid not null references public.projects(id),
 actor_id uuid not null references auth.users(id),
 actor_name text not null,
 action text not null check(action in ('create','update','archive','restore')),
 before_row jsonb,
 after_row jsonb not null,
 happened_at timestamptz not null default now()
);
create index history_project_idx on public.project_history(project_id,id desc);
alter table public.project_history enable row level security;
revoke all on public.project_history from anon,authenticated;
grant select on public.project_history to authenticated;
create policy member_history on public.project_history for select to authenticated using((select private.is_member()));

create function private.valid_payload(p jsonb) returns jsonb
language plpgsql set search_path='' as $$
declare r jsonb; k text; n numeric; y integer; m integer; d date;
begin
 if jsonb_typeof(p) is distinct from 'object' then raise exception 'INVALID_PAYLOAD'; end if;
 y=(p->>'year')::integer; m=(p->>'month')::integer;
 if y is null or y not between 2000 and 2100 or m is null or m not between 1 and 12 then raise exception 'INVALID_PERIOD'; end if;
 if length(btrim(coalesce(p->>'name',''))) not between 1 and 120 then raise exception 'INVALID_NAME'; end if;
 if p->>'status' is null or p->>'status' not in ('접수','작업중','작업완료','결제완료','캔슬') then raise exception 'INVALID_STATUS'; end if;
 r=jsonb_build_object('year',y,'month',m,'name',btrim(p->>'name'),'status',p->>'status');
 foreach k in array array['initial','final','invoiceAmount'] loop
  n=nullif(p->>k,'')::numeric;
  if n is not null and (n<0 or n>999999999999 or n<>trunc(n) or n::text in ('NaN','Infinity','-Infinity')) then raise exception 'INVALID_AMOUNT'; end if;
  r=r||jsonb_build_object(k,n);
 end loop;
 foreach k in array array['agency','production','director','pd','company','memo'] loop
  if length(coalesce(p->>k,'')) > (case when k='memo' then 3000 else 160 end) then raise exception 'TEXT_TOO_LONG'; end if;
  r=r||jsonb_build_object(k,btrim(coalesce(p->>k,'')));
 end loop;
 foreach k in array array['paidDate','invoiceDate'] loop
  d=nullif(p->>k,'')::date;
  if d is not null and (d<date '2000-01-01' or d>date '2100-12-31') then raise exception 'INVALID_DATE'; end if;
  r=r||jsonb_build_object(k,coalesce(to_char(d,'YYYY-MM-DD'),''));
 end loop;
 return r;
end; $$;
revoke all on function private.valid_payload(jsonb) from public,anon,authenticated;

create function private.audit_project() returns trigger language plpgsql security definer
set search_path='' as $$
declare who text; verb text;
begin
 select display_name into who from public.members where user_id=auth.uid() and active;
 if who is null then raise exception 'NOT_A_MEMBER' using errcode='42501'; end if;
 verb=case when TG_OP='INSERT' then 'create' when old.archived<>new.archived then case when new.archived then 'archive' else 'restore' end else 'update' end;
 insert into public.project_history(project_id,actor_id,actor_name,action,before_row,after_row)
 values(new.id,auth.uid(),who,verb,case when TG_OP='UPDATE' then to_jsonb(old) else null end,to_jsonb(new));
 return new;
end; $$;
revoke all on function private.audit_project() from public,anon,authenticated;
create trigger record_project_history after insert or update on public.projects for each row execute function private.audit_project();

create function public.save_project(p_id uuid,p_expected_version integer,p_payload jsonb)
returns public.projects language plpgsql security definer set search_path='' as $$
declare result public.projects; v_data jsonb;
begin
 if not private.is_member() then raise exception 'NOT_A_MEMBER' using errcode='42501'; end if;
 v_data=private.valid_payload(p_payload);
 if p_expected_version=0 then
  insert into public.projects(id,data,updated_by) values(p_id,v_data,auth.uid())
  on conflict(id) do nothing returning * into result;
 else
  update public.projects set data=v_data,version=version+1,updated_at=now(),updated_by=auth.uid()
  where id=p_id and version=p_expected_version and not archived returning * into result;
 end if;
 if result.id is null then raise exception 'VERSION_CONFLICT' using errcode='P0001'; end if;
 return result;
end; $$;
revoke all on function public.save_project(uuid,integer,jsonb) from public,anon;
grant execute on function public.save_project(uuid,integer,jsonb) to authenticated;

create function public.set_project_archived(p_id uuid,p_expected_version integer,p_archived boolean)
returns public.projects language plpgsql security definer set search_path='' as $$
declare result public.projects;
begin
 if not private.is_member() then raise exception 'NOT_A_MEMBER' using errcode='42501'; end if;
 update public.projects set archived=p_archived,version=version+1,updated_at=now(),updated_by=auth.uid()
 where id=p_id and version=p_expected_version returning * into result;
 if result.id is null then raise exception 'VERSION_CONFLICT'; end if;
 return result;
end; $$;
revoke all on function public.set_project_archived(uuid,integer,boolean) from public,anon;
grant execute on function public.set_project_archived(uuid,integer,boolean) to authenticated;

-- 한 파일은 한 트랜잭션으로 처리합니다. 한 행이라도 잘못되면 전체 취소됩니다.
create function public.import_projects(p_rows jsonb) returns jsonb
language plpgsql security definer set search_path='' as $$
declare row_data jsonb; payload jsonb; imported integer=0; skipped integer=0; date_value date; new_id uuid; key_value text;
begin
 if not private.is_member() then raise exception 'NOT_A_MEMBER' using errcode='42501'; end if;
 if jsonb_typeof(p_rows) is distinct from 'array' or jsonb_array_length(p_rows) not between 1 and 1000 then raise exception 'INVALID_IMPORT_SIZE'; end if;
 for row_data in select value from jsonb_array_elements(p_rows) loop
  payload=private.valid_payload(row_data->'data');
  key_value=row_data->>'import_key';
  if key_value is null or length(key_value) not between 1 and 240 then raise exception 'INVALID_IMPORT_KEY'; end if;
  date_value=nullif(row_data->>'created_on','')::date;
  if date_value is not null and (date_value<date '2000-01-01' or date_value>date '2100-12-31') then raise exception 'INVALID_DATE'; end if;
  new_id=null;
  insert into public.projects(id,data,created_on,import_key,updated_by)
  values((row_data->>'id')::uuid,payload,coalesce(date_value,(now() at time zone 'Asia/Seoul')::date),key_value,auth.uid())
  on conflict(import_key) do nothing returning id into new_id;
  if new_id is null then skipped=skipped+1; else imported=imported+1; end if;
 end loop;
 return jsonb_build_object('imported',imported,'skipped',skipped);
end; $$;
revoke all on function public.import_projects(jsonb) from public,anon;
grant execute on function public.import_projects(jsonb) to authenticated;

-- 하나의 SQL 조회 시점으로 전체 자료를 반환해, 페이지 분할 중 자료 추가로 인한 중복 집계를 막습니다.
create function public.list_projects() returns jsonb language plpgsql security definer set search_path='' as $$
declare result jsonb;
begin
 if not private.is_member() then raise exception 'NOT_A_MEMBER' using errcode='42501'; end if;
 select coalesce(jsonb_agg(to_jsonb(p) order by p.id),'[]'::jsonb) into result from public.projects p;
 return result;
end; $$;
revoke all on function public.list_projects() from public,anon;
grant execute on function public.list_projects() to authenticated;
commit;
