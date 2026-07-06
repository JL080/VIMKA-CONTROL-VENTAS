const ROLES = new Set(['gerente', 'admin', 'publicidad', 'coordinadora', 'jefe_ventas', 'asesor']);

function json(response, status, body) {
  response.setHeader('Cache-Control', 'no-store, max-age=0');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  return response.status(status).json(body);
}

function normalizeUsername(value) {
  return String(value || '').trim().toLowerCase();
}

function userEmail(username) {
  return `${username}@vimka.local`;
}

async function requestSupabase(path, { method = 'GET', body, token, serviceKey, anonKey, url }) {
  const key = serviceKey || anonKey;
  const response = await fetch(`${url}${path}`, {
    method,
    headers: {
      apikey: key,
      Authorization: `Bearer ${token || key}`,
      ...(body ? { 'Content-Type': 'application/json', Prefer: 'return=representation' } : {})
    },
    ...(body ? { body: JSON.stringify(body) } : {})
  });
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { message: text }; }
  if (!response.ok) throw new Error(data?.message || data?.msg || data?.error_description || `Supabase ${response.status}`);
  return data;
}

export default async function handler(request, response) {
  if (request.method !== 'POST') return json(response, 405, { error: 'Método no permitido' });

  const url = process.env.SUPABASE_URL;
  const anonKey = process.env.SUPABASE_ANON_KEY;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !anonKey || !serviceKey) return json(response, 500, { error: 'Variables de Supabase incompletas' });

  try {
    const authorization = request.headers.authorization || '';
    const accessToken = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
    if (!accessToken) return json(response, 401, { error: 'Sesión requerida' });

    const caller = await requestSupabase('/auth/v1/user', { token: accessToken, anonKey, url });
    const callerProfiles = await requestSupabase(`/rest/v1/profiles?id=eq.${encodeURIComponent(caller.id)}&select=id,role,active`, { serviceKey, url });
    const callerProfile = callerProfiles?.[0];
    if (!callerProfile?.active || callerProfile.role !== 'gerente') return json(response, 403, { error: 'Solo la gerencia puede gestionar usuarios' });

    const input = typeof request.body === 'string' ? JSON.parse(request.body) : (request.body || {});
    const action = input.action;

    if (action === 'list') {
      const users = await requestSupabase('/rest/v1/profiles?select=id,username,name,role,active,created_at&order=name.asc', { serviceKey, url });
      return json(response, 200, { users });
    }

    if (action === 'create') {
      const user = input.user || {};
      const username = normalizeUsername(user.user);
      const name = String(user.name || '').trim();
      const password = String(user.pass || '');
      const role = String(user.role || 'asesor');
      if (!/^[a-z0-9._-]{3,40}$/.test(username) || !name || password.length < 8 || !ROLES.has(role)) {
        return json(response, 400, { error: 'Datos de usuario inválidos' });
      }
      const created = await requestSupabase('/auth/v1/admin/users', {
        method: 'POST', body: { email: userEmail(username), password, email_confirm: true }, serviceKey, url
      });
      try {
        await requestSupabase('/rest/v1/profiles', {
          method: 'POST', body: { id: created.id, username, name, role, active: true }, serviceKey, url
        });
      } catch (error) {
        await requestSupabase(`/auth/v1/admin/users/${created.id}`, { method: 'DELETE', serviceKey, url }).catch(() => {});
        throw error;
      }
      return json(response, 201, { ok: true });
    }

    if (action === 'update') {
      const id = String(input.id || '');
      const updates = input.updates || {};
      const username = normalizeUsername(updates.user);
      const role = String(updates.role || '');
      if (id === caller.id && role && role !== 'gerente') return json(response, 400, { error: 'No puedes retirar tu propio rol de gerencia' });
      const profilePatch = {};
      const authPatch = {};
      if (updates.name) profilePatch.name = String(updates.name).trim();
      if (username) { if (!/^[a-z0-9._-]{3,40}$/.test(username)) return json(response, 400, { error: 'Usuario inválido' }); profilePatch.username = username; authPatch.email = userEmail(username); }
      if (role) { if (!ROLES.has(role)) return json(response, 400, { error: 'Rol inválido' }); profilePatch.role = role; }
      if (updates.password) { if (String(updates.password).length < 8) return json(response, 400, { error: 'La contraseña debe tener al menos 8 caracteres' }); authPatch.password = String(updates.password); }
      if (Object.keys(authPatch).length) await requestSupabase(`/auth/v1/admin/users/${id}`, { method: 'PUT', body: authPatch, serviceKey, url });
      if (Object.keys(profilePatch).length) await requestSupabase(`/rest/v1/profiles?id=eq.${encodeURIComponent(id)}`, { method: 'PATCH', body: profilePatch, serviceKey, url });
      return json(response, 200, { ok: true });
    }

    if (action === 'deactivate') {
      const id = String(input.id || '');
      if (!id || id === caller.id) return json(response, 400, { error: 'No puedes desactivar tu propia cuenta' });
      await requestSupabase(`/auth/v1/admin/users/${id}`, { method: 'PUT', body: { ban_duration: '876000h' }, serviceKey, url });
      await requestSupabase(`/rest/v1/profiles?id=eq.${encodeURIComponent(id)}`, { method: 'PATCH', body: { active: false }, serviceKey, url });
      return json(response, 200, { ok: true });
    }

    if (action === 'activate') {
      const id = String(input.id || '');
      if (!id) return json(response, 400, { error: 'Usuario inválido' });
      await requestSupabase(`/auth/v1/admin/users/${id}`, { method: 'PUT', body: { ban_duration: 'none' }, serviceKey, url });
      await requestSupabase(`/rest/v1/profiles?id=eq.${encodeURIComponent(id)}`, { method: 'PATCH', body: { active: true }, serviceKey, url });
      return json(response, 200, { ok: true });
    }

    if (action === 'delete') {
      const id = String(input.id || '');
      if (!id || id === caller.id) return json(response, 400, { error: 'No puedes eliminar tu propia cuenta' });
      const targets = await requestSupabase(`/rest/v1/profiles?id=eq.${encodeURIComponent(id)}&select=id,role,active`, { serviceKey, url });
      const target = targets?.[0];
      if (!target) return json(response, 404, { error: 'Usuario no encontrado' });
      if (target.role === 'gerente' && target.active) {
        const managers = await requestSupabase('/rest/v1/profiles?role=eq.gerente&active=eq.true&select=id', { serviceKey, url });
        if ((managers || []).length <= 1) return json(response, 400, { error: 'No puedes eliminar la única cuenta de gerencia' });
      }
      await requestSupabase(`/rest/v1/leads?owner_id=eq.${encodeURIComponent(id)}`, { method: 'PATCH', body: { owner_id: null }, serviceKey, url });
      await requestSupabase(`/rest/v1/leads?visitor_id=eq.${encodeURIComponent(id)}`, { method: 'PATCH', body: { visitor_id: null }, serviceKey, url });
      await requestSupabase(`/auth/v1/admin/users/${id}`, { method: 'DELETE', serviceKey, url });
      return json(response, 200, { ok: true });
    }

    return json(response, 400, { error: 'Acción inválida' });
  } catch (error) {
    console.error('[admin-users]', error);
    return json(response, 400, { error: error.message || 'Operación fallida' });
  }
}
