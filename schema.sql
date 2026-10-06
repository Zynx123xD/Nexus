-- NEXUS: esquema Supabase + RLS. Pégalo en Supabase > SQL Editor > Run.
create type user_status as enum ('ONLINE','IDLE','DO_NOT_DISTURB','OFFLINE');
create type channel_type as enum ('TEXT','VOICE');

create table profiles (
  id uuid primary key references auth.users on delete cascade,
  username text unique not null check (username ~ '^[a-z0-9_]{3,20}$'),
  display_name text not null,
  email text,
  avatar_url text, banner_url text, bio text default '',
  status user_status not null default 'OFFLINE',
  created_at timestamptz default now()
);
create table user_settings (
  user_id uuid primary key references profiles on delete cascade,
  theme text default 'dark', primary_color text default '#7C3AED',
  secondary_color text default '#06B6D4', ui_gradient boolean default true,
  animations boolean default true, blur boolean default true
);
create table friend_requests (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references profiles on delete cascade,
  receiver_id uuid not null references profiles on delete cascade,
  created_at timestamptz default now(),
  unique (sender_id, receiver_id), check (sender_id <> receiver_id)
);
create table friends (
  user_id uuid references profiles on delete cascade,
  friend_id uuid references profiles on delete cascade,
  created_at timestamptz default now(),
  primary key (user_id, friend_id)
);
create table blocked_users (
  blocker_id uuid references profiles on delete cascade,
  blocked_id uuid references profiles on delete cascade,
  primary key (blocker_id, blocked_id)
);
create table dm_conversations (id uuid primary key default gen_random_uuid(), created_at timestamptz default now());
create table dm_members (
  conversation_id uuid references dm_conversations on delete cascade,
  user_id uuid references profiles on delete cascade,
  primary key (conversation_id, user_id)
);
create table dm_messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references dm_conversations on delete cascade,
  author_id uuid not null references profiles on delete cascade,
  content text not null check (length(content) between 1 and 4000),
  reply_to uuid references dm_messages on delete set null,
  reactions jsonb not null default '{}',
  created_at timestamptz default now(), updated_at timestamptz
);
create table servers (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(name) between 1 and 60),
  icon_url text, banner_url text,
  owner_id uuid not null references profiles,
  invite_code text unique not null default substr(md5(random()::text),1,8),
  created_at timestamptz default now()
);
create table server_members (
  server_id uuid references servers on delete cascade,
  user_id uuid references profiles on delete cascade,
  joined_at timestamptz default now(),
  primary key (server_id, user_id)
);
create table roles (
  id uuid primary key default gen_random_uuid(),
  server_id uuid not null references servers on delete cascade,
  name text not null, color text default '#99AAB5', color2 text, color3 text,
  gradient boolean default false,
  gradient_dir text default 'diagonal' check (gradient_dir in ('horizontal','vertical','diagonal')),
  glow boolean default false, position int default 0,
  permissions jsonb not null default '{}'
);
create table member_roles (
  server_id uuid, user_id uuid,
  role_id uuid references roles on delete cascade,
  primary key (user_id, role_id),
  foreign key (server_id, user_id) references server_members on delete cascade
);
create table channels (
  id uuid primary key default gen_random_uuid(),
  server_id uuid not null references servers on delete cascade,
  name text not null, type channel_type not null default 'TEXT',
  position int default 0, category text
);
create table messages (
  id uuid primary key default gen_random_uuid(),
  channel_id uuid not null references channels on delete cascade,
  author_id uuid not null references profiles on delete cascade,
  content text not null check (length(content) between 1 and 4000),
  created_at timestamptz default now(), updated_at timestamptz
);
create index on messages (channel_id, created_at);
create index on dm_messages (conversation_id, created_at);

-- Helpers (security definer evita recursión en RLS)
create function is_member(s uuid) returns boolean language sql security definer stable set search_path=public
as $$ select exists(select 1 from server_members where server_id=s and user_id=auth.uid()) $$;
create function is_owner(s uuid) returns boolean language sql security definer stable set search_path=public
as $$ select exists(select 1 from servers where id=s and owner_id=auth.uid()) $$;
create function in_dm(c uuid) returns boolean language sql security definer stable set search_path=public
as $$ select exists(select 1 from dm_members where conversation_id=c and user_id=auth.uid()) $$;

-- Perfil automático al registrarse (también con Google)
create function handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
declare base text := lower(regexp_replace(split_part(new.email,'@',1),'[^a-z0-9_]','','gi')); u text;
begin
  base := coalesce(nullif(left(base,14),''),'user');
  u := base || substr(md5(new.id::text),1,5);
  insert into profiles(id,username,display_name,email,avatar_url)
  values(new.id,u,coalesce(new.raw_user_meta_data->>'full_name',base),new.email,new.raw_user_meta_data->>'avatar_url');
  insert into user_settings(user_id) values(new.id);
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function handle_new_user();

-- Crear servidor: owner, miembro, roles, canales (RPC atómica)
create function create_server(p_name text, p_icon text) returns uuid language plpgsql security definer set search_path=public as $$
declare s uuid; r uuid;
begin
  insert into servers(name,icon_url,owner_id) values(p_name,p_icon,auth.uid()) returning id into s;
  insert into server_members(server_id,user_id) values(s,auth.uid());
  insert into roles(server_id,name,position) values(s,'@everyone',0);
  insert into roles(server_id,name,color,position,permissions) values(s,'Owner','#F59E0B',100,'{"all":true}') returning id into r;
  insert into member_roles(server_id,user_id,role_id) values(s,auth.uid(),r);
  insert into channels(server_id,name,type,position,category) values
    (s,'general','TEXT',0,'GENERAL'),(s,'chat','TEXT',1,'GENERAL'),(s,'🔊 General','VOICE',2,'GENERAL');
  return s;
end $$;

-- Unirse por código
create function join_server(p_code text) returns uuid language plpgsql security definer set search_path=public as $$
declare s uuid;
begin
  select id into s from servers where invite_code=p_code;
  if s is null then raise exception 'Invitación inválida'; end if;
  insert into server_members(server_id,user_id) values(s,auth.uid()) on conflict do nothing;
  return s;
end $$;

-- Aceptar solicitud de amistad
create function accept_friend_request(p_id uuid) returns void language plpgsql security definer set search_path=public as $$
declare a uuid; b uuid;
begin
  select sender_id,receiver_id into a,b from friend_requests where id=p_id and receiver_id=auth.uid();
  if a is null then raise exception 'No existe'; end if;
  insert into friends values(a,b),(b,a) on conflict do nothing;
  delete from friend_requests where id=p_id;
end $$;

-- Abrir/obtener DM con otro usuario
create function open_dm(p_other uuid) returns uuid language plpgsql security definer set search_path=public as $$
declare c uuid;
begin
  select m1.conversation_id into c from dm_members m1 join dm_members m2 using(conversation_id)
   where m1.user_id=auth.uid() and m2.user_id=p_other limit 1;
  if c is null then
    insert into dm_conversations default values returning id into c;
    insert into dm_members values(c,auth.uid()),(c,p_other);
  end if;
  return c;
end $$;

-- RLS
alter table profiles enable row level security;
alter table user_settings enable row level security;
alter table friend_requests enable row level security;
alter table friends enable row level security;
alter table blocked_users enable row level security;
alter table dm_conversations enable row level security;
alter table dm_members enable row level security;
alter table dm_messages enable row level security;
alter table servers enable row level security;
alter table server_members enable row level security;
alter table roles enable row level security;
alter table member_roles enable row level security;
alter table channels enable row level security;
alter table messages enable row level security;

create policy p_read on profiles for select to authenticated using (true);
create policy p_upd on profiles for update using (id=auth.uid());
create policy us_all on user_settings for all using (user_id=auth.uid()) with check (user_id=auth.uid());
create policy fr_sel on friend_requests for select using (auth.uid() in (sender_id,receiver_id));
create policy fr_ins on friend_requests for insert with check (sender_id=auth.uid());
create policy fr_del on friend_requests for delete using (auth.uid() in (sender_id,receiver_id));
create policy f_sel on friends for select using (user_id=auth.uid());
create policy f_del on friends for delete using (auth.uid() in (user_id,friend_id));
create policy b_all on blocked_users for all using (blocker_id=auth.uid()) with check (blocker_id=auth.uid());
create policy dc_sel on dm_conversations for select using (in_dm(id));
create policy dmm_sel on dm_members for select using (in_dm(conversation_id));
create policy dmsg_sel on dm_messages for select using (in_dm(conversation_id));
create policy dmsg_ins on dm_messages for insert with check (author_id=auth.uid() and in_dm(conversation_id));
create policy dmsg_upd on dm_messages for update using (in_dm(conversation_id)); -- reacciones; edición propia se valida en la app/trigger
create policy dmsg_del on dm_messages for delete using (author_id=auth.uid());
create policy s_sel on servers for select using (is_member(id) or owner_id=auth.uid());
create policy s_upd on servers for update using (owner_id=auth.uid());
create policy s_del on servers for delete using (owner_id=auth.uid());
create policy sm_sel on server_members for select using (is_member(server_id));
create policy sm_del on server_members for delete using (user_id=auth.uid() or is_owner(server_id));
create policy r_sel on roles for select using (is_member(server_id));
create policy r_all on roles for all using (is_owner(server_id)) with check (is_owner(server_id));
create policy mr_sel on member_roles for select using (is_member(server_id));
create policy mr_all on member_roles for all using (is_owner(server_id)) with check (is_owner(server_id));
create policy c_sel on channels for select using (is_member(server_id));
create policy c_all on channels for all using (is_owner(server_id)) with check (is_owner(server_id));
create policy m_sel on messages for select using (is_member((select server_id from channels where id=channel_id)));
create policy m_ins on messages for insert with check (author_id=auth.uid() and is_member((select server_id from channels where id=channel_id)));
create policy m_upd on messages for update using (author_id=auth.uid());
create policy m_del on messages for delete using (author_id=auth.uid());

-- Realtime
alter publication supabase_realtime add table messages, dm_messages, friend_requests, friends, profiles, server_members, member_roles, roles, channels;

-- Storage: crea en el panel los buckets públicos "avatars" y "server-icons".
