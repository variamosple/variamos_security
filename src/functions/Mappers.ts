import { Nullable, SessionInfo, SessionUser } from "../types";

export const sessionInfoToSessionUser = (
  sessionInfo: Nullable<SessionInfo>
): SessionUser | null => {
  if (!sessionInfo || Object.keys(sessionInfo).length == 0) {
    return null;
  }

  const { sub, name, userName: user, email, roles, permissions } = sessionInfo;

  return { id: sub, name, user, email, roles, permissions };
};
