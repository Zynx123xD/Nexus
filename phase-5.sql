-- NEXUS fase 5-6. Ejecutar UNA vez en Supabase > SQL Editor (después de schema.sql). No borra tablas.
create or replace function send_friend_request(p_username text) returns text language plpgsql security definer set search_path=public as $$
declare t uuid; me uuid:=auth.uid(); rid uuid;
begin
  select id into t from profiles where username=lower(trim(p_username));
  if t is null then raise exception 'Usuario no encontrado'; end if;
  if t=me then raise exception 'No puedes añadirte a ti mismo'; end if;
  if exists(select 1 from blocked_users where (blocker_id=me and blocked_id=t) or (blocker_id=t and blocked_id=me)) then raise exception 'No es posible enviar la solicitud'; end if;
  if exists(select 1 from friends where user_id=me and friend_id=t) then raise exception 'Ya son amigos'; end if;
  select id into rid from friend_requests where sender_id=t and receiver_id=me;
  if rid is not null then perform accept_friend_request(rid); return 'accepted'; end if;
  insert into friend_requests(sender_id,receiver_id) values(me,t) on conflict do nothing;
  return 'sent';
end $$;

create or replace function remove_friend(p_id uuid) returns void language sql security definer set search_path=public as $$
  delete from friends where (user_id=auth.uid() and friend_id=p_id) or (user_id=p_id and friend_id=auth.uid()) $$;

create or replace function block_user(p_id uuid) returns void language plpgsql security definer set search_path=public as $$
begin
  if p_id=auth.uid() then raise exception 'Operación inválida'; end if;
  insert into blocked_users values(auth.uid(),p_id) on conflict do nothing;
  delete from friends where (user_id=auth.uid() and friend_id=p_id) or (user_id=p_id and friend_id=auth.uid());
  delete from friend_requests where (sender_id=auth.uid() and receiver_id=p_id) or (sender_id=p_id and receiver_id=auth.uid());
end $$;

-- open_dm: ahora solo entre amigos
create or replace function open_dm(p_other uuid) returns uuid language plpgsql security definer set search_path=public as $$
declare c uuid;
begin
  if not exists(select 1 from friends where user_id=auth.uid() and friend_id=p_other) then raise exception 'Solo puedes escribir a tus amigos'; end if;
  select m1.conversation_id into c from dm_members m1 join dm_members m2 using(conversation_id)
   where m1.user_id=auth.uid() and m2.user_id=p_other limit 1;
  if c is null then
    insert into dm_conversations default values returning id into c;
    insert into dm_members values(c,auth.uid()),(c,p_other);
  end if;
  return c;
end $$;

-- No enviar DMs si hay bloqueo entre los participantes
create or replace function dm_blocked(c uuid) returns boolean language sql security definer stable set search_path=public as $$
  select exists(select 1 from dm_members dm join blocked_users b
    on (b.blocker_id=dm.user_id and b.blocked_id=auth.uid()) or (b.blocker_id=auth.uid() and b.blocked_id=dm.user_id)
    where dm.conversation_id=c and dm.user_id<>auth.uid()) $$;
drop policy if exists dmsg_ins on dm_messages;
create policy dmsg_ins on dm_messages for insert with check (author_id=auth.uid() and in_dm(conversation_id) and not dm_blocked(conversation_id));
-- cierra un hueco: antes cualquier miembro podía editar mensajes ajenos
drop policy if exists dmsg_upd on dm_messages;
create policy dmsg_upd on dm_messages for update using (author_id=auth.uid());
