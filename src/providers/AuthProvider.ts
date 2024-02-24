import { signIn, SignInInput, SignInOutput, signOut, fetchAuthSession } from "aws-amplify/auth";

export interface AuthProviderOptions {
  authGroups?: string[];
}

const defaultOptions = {
  authGroups: [],
};

export class AuthProvider {
  public authGroups: string[];

  public constructor(options?: AuthProviderOptions) {
    this.authGroups = options?.authGroups || defaultOptions.authGroups;
  }

  public login = (input: SignInInput): Promise<SignInOutput> => {
    return signIn(input);
  };

  public logout = (): Promise<void> => {
    return signOut();
  };

  public checkAuth = async (): Promise<void> => {
    const session = await fetchAuthSession();

    if (this.authGroups.length === 0) {
      return;
    }

    const userGroups = session.tokens?.accessToken.payload["cognito:groups"];

    if (!userGroups) {
      throw new Error("Unauthorized");
    }

    for (const group of userGroups as string[]) {
      if (this.authGroups.includes(group)) {
        return;
      }
    }

    throw new Error("Unauthorized");
  };

  public checkError = (): Promise<void> => {
    return Promise.resolve();
  };

  public getPermissions = async (): Promise<string[]> => {
    const session = await fetchAuthSession();
    const userGroups = session.tokens?.accessToken.payload["cognito:groups"];

    return userGroups ? Promise.resolve(userGroups as string[]) : Promise.reject();
  };
}
