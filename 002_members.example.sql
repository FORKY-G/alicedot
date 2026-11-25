-- Supabase Authentication > Users에서 각 구성원의 계정을 먼저 만드세요.
-- 이메일/표시 이름을 실제 구성원으로 바꾼 뒤 SQL Editor에서 실행하세요.
-- 이 파일에 실제 이메일을 채운 사본은 GitHub에 올리지 마세요.
insert into public.members(user_id,display_name,active)
select id,'포키',true from auth.users where lower(email)=lower('CHANGE_ME@example.com')
on conflict(user_id) do update set display_name=excluded.display_name,active=true;

-- 대표님마다 위 문장을 복사해 이메일과 이름을 바꾸세요. 모두 입력·수정 가능합니다.
-- 접근 해제는 아래 형태로 수행합니다. 기존 이력은 남습니다.
-- update public.members set active=false where user_id='해당 사용자 UUID';
