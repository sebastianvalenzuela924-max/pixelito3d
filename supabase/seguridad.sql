-- =====================================================================
-- Pixelito3D · Endurecimiento de seguridad (ejecutar UNA vez)
-- Proyecto Supabase: ywocbwnfgglfksbzkngw
--
-- ORDEN (importante):
--  1) Supabase > Authentication > Providers > Email: desactiva "Confirm email"
--     y sube "Minimum password length" a 8 o más.
--  2) Supabase > Authentication > Users > Add user > "Create new user"
--     (marca "Auto Confirm User") con contraseñas LARGAS y únicas:
--        seba@pixelito3d.app
--        cami@pixelito3d.app
--  3) Pega TODO este archivo en SQL Editor y ejecútalo (Run).
--  4) Recién entonces fusiona la rama "seguridad-y-reparto" a master.
-- =====================================================================

-- ---------- Tablas nuevas ----------
create table if not exists public.catalogo_publico (
  id bigint primary key,
  nombre text not null,
  imagen_url text,
  color_id bigint,
  colores_config jsonb,
  gramos numeric default 0,
  pintura boolean default false,
  descuento numeric default 0,
  precio_base numeric,
  precios jsonb default '{}'::jsonb,
  updated_at timestamptz default now()
);

create table if not exists public.colores_publico (
  id bigint primary key,
  nombre text not null,
  hex text
);

-- admin_users: ahora solo enlaza cuentas de Supabase Auth (sin contraseñas)
drop table if exists public.admin_users cascade;
create table public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique,
  display_name text
);

insert into public.admin_users (user_id, username, display_name)
select id, 'seba', 'Seba' from auth.users where email = 'seba@pixelito3d.app';
insert into public.admin_users (user_id, username, display_name)
select id, 'cami', 'Camila' from auth.users where email = 'cami@pixelito3d.app';

-- ---------- Clientes: sin hash de contraseña, ligados a Supabase Auth ----------
alter table public.clientes add column if not exists auth_id uuid unique references auth.users(id) on delete cascade;
alter table public.clientes drop column if exists pass_hash;

-- Cuentas antiguas (sin Auth): liberar el nombre de usuario para que puedan registrarse de nuevo
update public.clientes set usuario = usuario || '_antiguo' where auth_id is null and usuario not like '%\_antiguo';

-- pedidos.items debe ser jsonb
alter table public.pedidos alter column items type jsonb using items::jsonb;

-- ---------- Función de admin ----------
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admin_users where user_id = auth.uid());
$$;
revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to anon, authenticated;

-- Ids de cliente del usuario conectado (función segura: el público no puede leer la tabla clientes)
create or replace function public.mis_clientes()
returns setof text language sql stable security definer set search_path = public as $$
  select id from public.clientes where auth_id = auth.uid();
$$;
revoke all on function public.mis_clientes() from public;
grant execute on function public.mis_clientes() to anon, authenticated;

-- ---------- Semilla del catálogo público (hasta que entres como admin y se sincronice con precios por color) ----------
insert into public.colores_publico (id, nombre, hex)
select id, nombre, hex from public.colores
on conflict (id) do update set nombre = excluded.nombre, hex = excluded.hex;

insert into public.catalogo_publico (id, nombre, imagen_url, color_id, colores_config, gramos, pintura, descuento, precio_base)
select id, nombre, imagen_url, color_id, colores_config, gramos, coalesce(pintura,false), coalesce(descuento,0), precio_venta
from public.productos
where visible is not false
on conflict (id) do nothing;

-- ---------- Borrar TODAS las políticas anteriores (eran abiertas al público) ----------
do $$
declare r record;
begin
  for r in select schemaname, tablename, policyname from pg_policies
           where schemaname = 'public'
             and tablename in ('ajustes','colores','productos','ventas','movimientos','clientes','pedidos','admin_users','catalogo_publico','colores_publico')
  loop
    execute format('drop policy if exists %I on %I.%I', r.policyname, r.schemaname, r.tablename);
  end loop;
end $$;

alter table public.ajustes          enable row level security;
alter table public.colores          enable row level security;
alter table public.productos        enable row level security;
alter table public.ventas           enable row level security;
alter table public.movimientos      enable row level security;
alter table public.clientes         enable row level security;
alter table public.pedidos          enable row level security;
alter table public.admin_users      enable row level security;
alter table public.catalogo_publico enable row level security;
alter table public.colores_publico  enable row level security;

-- Datos internos: el público (anon) no tiene acceso alguno
revoke all on public.ajustes, public.colores, public.productos, public.ventas,
              public.movimientos, public.admin_users from anon;

-- Solo administradores: ajustes, colores (con precio por kilo), productos (costos), ventas, movimientos
create policy admin_all on public.ajustes     for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy admin_all on public.colores     for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy admin_all on public.productos   for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy admin_all on public.ventas      for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy admin_all on public.movimientos for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- admin_users: cada admin solo ve su propia fila
create policy admin_self on public.admin_users for select to authenticated using (user_id = auth.uid());

-- Catálogo público: todos leen, solo admin escribe
create policy lectura_publica on public.catalogo_publico for select to anon, authenticated using (true);
create policy admin_escribe   on public.catalogo_publico for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy lectura_publica on public.colores_publico  for select to anon, authenticated using (true);
create policy admin_escribe   on public.colores_publico  for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- Clientes: cada uno ve/edita solo lo suyo; admin ve todo
revoke all on public.clientes from anon;
create policy cli_select on public.clientes for select to authenticated using (auth_id = auth.uid() or public.is_admin());
create policy cli_insert on public.clientes for insert to authenticated
  with check ((auth_id = auth.uid() and char_length(coalesce(nombre,'')) <= 60 and char_length(coalesce(usuario,'')) between 3 and 30
               and char_length(coalesce(contacto,'')) <= 120) or public.is_admin());
create policy cli_update on public.clientes for update to authenticated
  using (auth_id = auth.uid() or public.is_admin()) with check (auth_id = auth.uid() or public.is_admin());
create policy cli_delete on public.clientes for delete to authenticated using (public.is_admin());

-- Un cliente NO puede cambiarse puntos ni premios (solo el admin)
create or replace function public.clientes_proteger()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if public.is_admin() then return new; end if;
  if tg_op = 'INSERT' then
    new.auth_id := auth.uid();
    new.compras_piezas := 0;
    new.gramos_comprados := 0;
    new.premios_canjeados := 0;
  else
    new.id := old.id;
    new.auth_id := old.auth_id;
    new.usuario := old.usuario;
    new.compras_piezas := old.compras_piezas;
    new.gramos_comprados := old.gramos_comprados;
    new.premios_canjeados := old.premios_canjeados;
  end if;
  return new;
end $$;
drop trigger if exists trg_clientes_proteger on public.clientes;
create trigger trg_clientes_proteger before insert or update on public.clientes
  for each row execute function public.clientes_proteger();

-- Pedidos: cualquiera puede CREAR (validado); solo admin lee todo; cada cliente lee los suyos.
-- El link de un pedido se abre con la función get_pedido (no se puede listar ni adivinar).
create policy ped_insert on public.pedidos for insert to anon, authenticated
  with check (
    estado = 'pendiente'
    and aprobado_por is null and aprobado_at is null
    and id ~ '^[A-Za-z0-9-]{6,24}$'
    and jsonb_typeof(items) = 'array' and jsonb_array_length(items) between 1 and 60
    and total_venta between 0 and 100000000
    and char_length(coalesce(cliente_nombre,'')) <= 120
    and char_length(coalesce(cliente_contacto,'')) <= 160
    and (cliente_id is null or cliente_id in (select public.mis_clientes()))
  );
create policy ped_select on public.pedidos for select to authenticated
  using (public.is_admin() or cliente_id in (select public.mis_clientes()));
create policy ped_update on public.pedidos for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy ped_delete on public.pedidos for delete to authenticated using (public.is_admin());
revoke select, update, delete on public.pedidos from anon;

-- Ver un pedido por su link (sin costos para el público)
create or replace function public.get_pedido(p_id text)
returns setof public.pedidos language plpgsql stable security definer set search_path = public as $$
declare r public.pedidos;
begin
  if p_id is null or p_id !~ '^[A-Za-z0-9-]{6,24}$' then return; end if;
  select * into r from public.pedidos where id = p_id;
  if not found then return; end if;
  if not public.is_admin() then
    -- ids antiguos (cortos) solo los ve su dueño; los nuevos se abren con el link
    if char_length(r.id) < 12
       and not (r.cliente_id is not null and r.cliente_id in (select id from public.clientes where auth_id = auth.uid())) then
      return;
    end if;
    r.total_costo := 0;
    r.items := coalesce((
      select jsonb_agg(i - 'costoUnitario' - 'horas' - 'pinturaManual' - 'splitMine' - 'imagenUrl')
      from jsonb_array_elements(r.items) i), '[]'::jsonb);
  end if;
  return next r;
end $$;
revoke all on function public.get_pedido(text) from public;
grant execute on function public.get_pedido(text) to anon, authenticated;

-- Eliminar un pedido: admin, su dueño, o quien tenga el link de un pedido PENDIENTE nuevo
create or replace function public.eliminar_pedido(p_id text)
returns boolean language plpgsql security definer set search_path = public as $$
declare r public.pedidos;
begin
  if p_id is null or p_id !~ '^[A-Za-z0-9-]{6,24}$' then return false; end if;
  select * into r from public.pedidos where id = p_id;
  if not found then return false; end if;
  if public.is_admin()
     or (r.estado = 'pendiente' and char_length(r.id) >= 12)
     or (r.cliente_id is not null and r.cliente_id in (select id from public.clientes where auth_id = auth.uid())) then
    delete from public.pedidos where id = p_id;
    return true;
  end if;
  return false;
end $$;
revoke all on function public.eliminar_pedido(text) from public;
grant execute on function public.eliminar_pedido(text) to anon, authenticated;

-- Pedidos antiguos: borrar costos que quedaron guardados dentro de los artículos
update public.pedidos
set items = coalesce((select jsonb_agg(i - 'costoUnitario' - 'horas' - 'pinturaManual')
                      from jsonb_array_elements(items) i), '[]'::jsonb)
where estado = 'pendiente';

-- Comprobar si un usuario de cliente está libre (para registrarse sin dejar cuentas a medias)
create or replace function public.usuario_disponible(p_usuario text)
returns boolean language sql stable security definer set search_path = public as $$
  select not exists (select 1 from public.clientes where lower(usuario) = lower(p_usuario));
$$;
revoke all on function public.usuario_disponible(text) from public;
grant execute on function public.usuario_disponible(text) to anon, authenticated;
