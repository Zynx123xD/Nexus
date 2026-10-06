-- NEXUS fase 8 (roles). Ejecutar UNA vez en SQL Editor, después de schema.sql y phase-5.sql. No borra datos.
alter table roles add column if not exists kind text not null default 'custom' check (kind in ('custom','owner','everyone'));
alter table roles add column if not exists glow_intensity int not null default 8 check (glow_intensity between 0 and 30);
update roles set kind='everyone' where name='@everyone' and position=0;
update roles set kind='owner' where name='Owner' and position=100;

-- Las escrituras directas a roles/member_roles se cierran: todo pasa por las funciones de abajo (validan permisos y jerarquía).
drop policy if exists r_all on roles;
drop policy if exists mr_all on member_roles;

-- Poder del usuario en un servidor: owner=1000; admin = mayor posición entre sus roles con manage_roles; -1 = sin poder.
create or replace function role_power(s uuid) returns int language sql security definer stable set search_path=public as $$
  select case when exists(select 1 from servers where id=s and owner_id=auth.uid()) then 1000
    else coalesce((select max(r.position) from member_roles mr join roles r on r.id=mr.role_id
      where mr.server_id=s and mr.user_id=auth.uid() and (r.permissions->>'manage_roles')='true'),-1) end $$;

create or replace function chk_role(n text,c1 text,c2 text,c3 text,d text,gi int) returns void language plpgsql immutable as $$
begin
  if n is null or length(trim(n)) not between 1 and 32 or lower(trim(n)) in ('@everyone','everyone') then raise exception 'Nombre de rol inválido'; end if;
  if c1 is null or c1 !~ '^#[0-9a-fA-F]{6}$' or (c2 is not null and c2 !~ '^#[0-9a-fA-F]{6}$') or (c3 is not null and c3 !~ '^#[0-9a-fA-F]{6}$') then raise exception 'Color inválido'; end if;
  if d not in ('horizontal','vertical','diagonal') then raise exception 'Dirección inválida'; end if;
  if gi not between 0 and 30 then raise exception 'Intensidad inválida'; end if;
end $$;

create or replace function create_role(p_server uuid,p_name text,p_color text,p_color2 text,p_color3 text,p_gradient boolean,p_dir text,p_glow boolean,p_glow_int int,p_manage boolean)
returns uuid language plpgsql security definer set search_path=public as $$
declare pw int:=role_power(p_server); pos int; rid uuid;
begin
  if pw<0 then raise exception 'Sin permiso para gestionar roles'; end if;
  perform chk_role(p_name,p_color,p_color2,p_color3,p_dir,p_glow_int);
  if coalesce(p_manage,false) and pw<1000 then raise exception 'Solo el owner puede conceder gestión de roles'; end if;
  select least(98,coalesce(max(position),0)+1,pw-1) into pos from roles where server_id=p_server and kind='custom';
  if pos<1 then raise exception 'Tu rol es demasiado bajo para crear roles'; end if;
  insert into roles(server_id,name,color,color2,color3,gradient,gradient_dir,glow,glow_intensity,position,permissions)
  values(p_server,trim(p_name),p_color,p_color2,p_color3,p_gradient,p_dir,p_glow,p_glow_int,pos,jsonb_build_object('manage_roles',coalesce(p_manage,false)))
  returning id into rid;
  return rid;
end $$;

create or replace function update_role(p_id uuid,p_name text,p_color text,p_color2 text,p_color3 text,p_gradient boolean,p_dir text,p_glow boolean,p_glow_int int,p_manage boolean)
returns void language plpgsql security definer set search_path=public as $$
declare r roles; pw int;
begin
  select * into r from roles where id=p_id;
  if not found then raise exception 'El rol no existe'; end if;
  pw:=role_power(r.server_id);
  if pw<0 or (pw<1000 and r.position>=pw) then raise exception 'Sin permiso sobre este rol (jerarquía)'; end if;
  if r.kind='everyone' then raise exception '@everyone no se edita'; end if;
  if r.kind='owner' and (pw<1000 or p_name<>r.name) then raise exception 'El rol Owner está protegido'; end if;
  perform chk_role(p_name,p_color,p_color2,p_color3,p_dir,p_glow_int);
  if pw<1000 and coalesce(p_manage,false) is distinct from coalesce((r.permissions->>'manage_roles')='true',false) then raise exception 'Solo el owner cambia permisos'; end if;
  update roles set name=trim(p_name),color=p_color,color2=p_color2,color3=p_color3,gradient=p_gradient,gradient_dir=p_dir,glow=p_glow,glow_intensity=p_glow_int,
    permissions=case when r.kind='owner' then permissions else jsonb_set(permissions,'{manage_roles}',to_jsonb(coalesce(p_manage,false))) end
  where id=p_id;
end $$;

create or replace function delete_role(p_id uuid) returns void language plpgsql security definer set search_path=public as $$
declare r roles; pw int;
begin
  select * into r from roles where id=p_id;
  if not found then return; end if;
  pw:=role_power(r.server_id);
  if r.kind<>'custom' then raise exception 'Los roles del sistema no se eliminan'; end if;
  if pw<0 or (pw<1000 and r.position>=pw) then raise exception 'Sin permiso sobre este rol (jerarquía)'; end if;
  delete from roles where id=p_id;
end $$;

create or replace function move_role(p_id uuid,p_up boolean) returns void language plpgsql security definer set search_path=public as $$
declare r roles; pw int; pos int; tgt int; mx int;
begin
  select * into r from roles where id=p_id;
  if not found or r.kind<>'custom' then raise exception 'Rol no movible'; end if;
  pw:=role_power(r.server_id);
  if pw<0 or (pw<1000 and r.position>=pw) then raise exception 'Sin permiso sobre este rol (jerarquía)'; end if;
  with o as (select id,row_number() over(order by position,id) rn from roles where server_id=r.server_id and kind='custom')
    update roles x set position=o.rn from o where x.id=o.id;
  select position into pos from roles where id=p_id;
  select max(position) into mx from roles where server_id=r.server_id and kind='custom';
  tgt:=pos+case when p_up then 1 else -1 end;
  if tgt<1 or tgt>mx then return; end if;
  if pw<1000 and tgt>=pw then raise exception 'No puedes subir el rol por encima del tuyo'; end if;
  update roles set position=case when id=p_id then tgt else pos end
   where server_id=r.server_id and kind='custom' and position in (pos,tgt);
end $$;

create or replace function assign_role(p_role uuid,p_user uuid,p_on boolean) returns void language plpgsql security definer set search_path=public as $$
declare r roles; pw int; ttop int;
begin
  select * into r from roles where id=p_role;
  if not found then raise exception 'El rol no existe'; end if;
  pw:=role_power(r.server_id);
  if pw<0 then raise exception 'Sin permiso para gestionar roles'; end if;
  if r.kind<>'custom' then raise exception 'Este rol no es asignable'; end if;
  if pw<1000 and r.position>=pw then raise exception 'Jerarquía: el rol es superior al tuyo'; end if;
  if not exists(select 1 from server_members where server_id=r.server_id and user_id=p_user) then raise exception 'No es miembro del servidor'; end if;
  if pw<1000 then
    select coalesce(max(x.position),0) into ttop from member_roles m join roles x on x.id=m.role_id where m.server_id=r.server_id and m.user_id=p_user;
    if ttop>=pw or exists(select 1 from servers where id=r.server_id and owner_id=p_user) then raise exception 'Jerarquía: no puedes modificar a este miembro'; end if;
  end if;
  if p_on then insert into member_roles(server_id,user_id,role_id) values(r.server_id,p_user,p_role) on conflict do nothing;
  else delete from member_roles where user_id=p_user and role_id=p_role; end if;
end $$;

-- create_server actualizado: marca los roles del sistema con "kind"
create or replace function create_server(p_name text,p_icon text) returns uuid language plpgsql security definer set search_path=public as $$
declare s uuid; r uuid;
begin
  insert into servers(name,icon_url,owner_id) values(p_name,p_icon,auth.uid()) returning id into s;
  insert into server_members(server_id,user_id) values(s,auth.uid());
  insert into roles(server_id,name,position,kind) values(s,'@everyone',0,'everyone');
  insert into roles(server_id,name,color,position,kind,permissions) values(s,'Owner','#F59E0B',100,'owner','{"all":true,"manage_roles":true}') returning id into r;
  insert into member_roles(server_id,user_id,role_id) values(s,auth.uid(),r);
  insert into channels(server_id,name,type,position,category) values
    (s,'general','TEXT',0,'GENERAL'),(s,'chat','TEXT',1,'GENERAL'),(s,'🔊 General','VOICE',2,'GENERAL');
  return s;
end $$;
