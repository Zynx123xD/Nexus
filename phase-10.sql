-- NEXUS fase 10 (chat: editar, borrar, responder, reacciones). Ejecutar UNA vez, después de schema.sql, phase-5.sql y phase-8.sql.
alter table messages add column if not exists reply_to uuid references messages(id) on delete set null;

-- Solo se puede cambiar el contenido (y updated_at lo fija el servidor). Impide mover/reasignar mensajes por la API.
create or replace function guard_msg_update() returns trigger language plpgsql as $$
begin
  if (to_jsonb(new)-'content'-'updated_at'-'reactions') is distinct from (to_jsonb(old)-'content'-'updated_at'-'reactions') then
    raise exception 'Solo se puede editar el contenido del mensaje';
  end if;
  new.updated_at := case when new.content is distinct from old.content then now() else old.updated_at end;
  return new;
end $$;
drop trigger if exists t_guard_messages on messages;
create trigger t_guard_messages before update on messages for each row execute function guard_msg_update();
drop trigger if exists t_guard_dm_messages on dm_messages;
create trigger t_guard_dm_messages before update on dm_messages for each row execute function guard_msg_update();

-- Políticas: editar = solo autor (y aún miembro); borrar = autor, o owner/admin (role_power>=0) en canales
drop policy if exists m_upd on messages;
create policy m_upd on messages for update using (author_id=auth.uid() and is_member((select server_id from channels where id=channel_id)))
  with check (author_id=auth.uid());
drop policy if exists m_del on messages;
create policy m_del on messages for delete using (
  (author_id=auth.uid() and is_member((select server_id from channels where id=channel_id)))
  or role_power((select server_id from channels where id=channel_id))>=0);
drop policy if exists dmsg_upd on dm_messages;
create policy dmsg_upd on dm_messages for update using (author_id=auth.uid() and in_dm(conversation_id)) with check (author_id=auth.uid());
drop policy if exists dmsg_del on dm_messages;
create policy dmsg_del on dm_messages for delete using (author_id=auth.uid() and in_dm(conversation_id));

create or replace function msg_server(m uuid) returns uuid language sql security definer stable set search_path=public as $$
  select c.server_id from messages x join channels c on c.id=x.channel_id where x.id=m $$;
create or replace function dm_conv(m uuid) returns uuid language sql security definer stable set search_path=public as $$
  select conversation_id from dm_messages where id=m $$;

create table if not exists message_reactions(
  message_id uuid not null references messages on delete cascade,
  user_id uuid not null references profiles on delete cascade,
  emoji text not null check (length(emoji) between 1 and 16),
  created_at timestamptz default now(),
  primary key (message_id,user_id,emoji));
create table if not exists dm_message_reactions(
  message_id uuid not null references dm_messages on delete cascade,
  user_id uuid not null references profiles on delete cascade,
  emoji text not null check (length(emoji) between 1 and 16),
  created_at timestamptz default now(),
  primary key (message_id,user_id,emoji));
alter table message_reactions enable row level security;
alter table dm_message_reactions enable row level security;
create policy mrx_sel on message_reactions for select using (is_member(msg_server(message_id)));
create policy mrx_ins on message_reactions for insert with check (user_id=auth.uid() and is_member(msg_server(message_id)));
create policy mrx_del on message_reactions for delete using (user_id=auth.uid());
create policy dmrx_sel on dm_message_reactions for select using (in_dm(dm_conv(message_id)));
create policy dmrx_ins on dm_message_reactions for insert with check (user_id=auth.uid() and in_dm(dm_conv(message_id)) and not dm_blocked(dm_conv(message_id)));
create policy dmrx_del on dm_message_reactions for delete using (user_id=auth.uid());
alter table message_reactions replica identity full;
alter table dm_message_reactions replica identity full;
alter publication supabase_realtime add table message_reactions, dm_message_reactions;
