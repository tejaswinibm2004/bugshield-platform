// Profile loader
export function loadProfile(session) {
  let user = null;
  if (session && session.token) {
    user = session.user;
  }
  return user.name;
}
