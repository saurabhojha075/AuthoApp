/**
 * JBoss, Home of Professional Open Source
 * Copyright Red Hat, Inc., and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.authoapp;

import android.app.Activity;
import android.util.Log;
import android.util.Pair;
import android.widget.Toast;

import org.jboss.aerogear.android.authorization.AuthorizationManager;
import org.jboss.aerogear.android.authorization.AuthzModule;
import org.jboss.aerogear.android.authorization.oauth2.OAuth2AuthorizationConfiguration;
import org.jboss.aerogear.android.authorization.oauth2.OAuthWebViewDialog;
import org.jboss.aerogear.android.core.Callback;
import org.jboss.aerogear.android.pipe.PipeManager;
import org.jboss.aerogear.android.pipe.rest.RestfulPipeConfiguration;
import org.jboss.aerogear.android.pipe.rest.multipart.MultipartRequestBuilder;

import java.io.File;
import java.net.URL;

public class KeycloakHelper {
    private static final String EDU_FRONT_SERVER_URL = "http://qa.myedufront.com";
    private static final String AUTHZ_URL = EDU_FRONT_SERVER_URL +"/auth";
    private static final String AUTHZ_ENDPOINT = "/realms/dev/protocol/openid-connect/auth";
    private static final String ACCESS_TOKEN_ENDPOINT = "/realms/dev/protocol/openid-connect/token";
    private static final String REFRESH_TOKEN_ENDPOINT = "/realms/dev/tokens/refresh";
    private static final String AUTHZ_ACCOOUNT_ID = "keycloak-token";
    private static final String AUTHZ_CLIENT_ID = "edufront-dev-service";
    private static final String AUTHZ_REDIRECT_URL = "http://qa.myedufront.com/*";
    private static final String MODULE_NAME = "KeyCloakAuthz";

    static
    {
        try
        {
            AuthorizationManager
                    .config(MODULE_NAME, OAuth2AuthorizationConfiguration.class)
                    .setBaseURL(new URL(AUTHZ_URL))
                    .setAuthzEndpoint(AUTHZ_ENDPOINT)
                    .setAccessTokenEndpoint(ACCESS_TOKEN_ENDPOINT)
                    .setRefreshEndpoint(ACCESS_TOKEN_ENDPOINT)
                    .setAccountId(AUTHZ_ACCOOUNT_ID)
                    .setClientId(AUTHZ_CLIENT_ID)
                    .setRedirectURL(AUTHZ_REDIRECT_URL)
                    /*.addAdditionalAuthorizationParam((Pair.create("grant_type", "password")))
                    .addAdditionalAuthorizationParam((Pair.create("username", "admin")))
                    .addAdditionalAuthorizationParam((Pair.create("password", "admin")))*/
                    .asModule();

            PipeManager.config("kc-upload", RestfulPipeConfiguration.class)
                    .module(AuthorizationManager.getModule(MODULE_NAME))
                    .requestBuilder(new MultipartRequestBuilder());

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void connect(final Activity activity, final Callback callback)
    {



        try {
            final AuthzModule authzModule = AuthorizationManager.getModule("KeyCloakAuthz");
            authzModule.requestAccess(activity, new Callback<String>()
            {
                @SuppressWarnings("unchecked")
                @Override
                public void onSuccess(String s)
                {

                    Log.v("yoyy__________",s+"kotu");
                    callback.onSuccess(s);
                }

                @Override
                public void onFailure(Exception e)
                {
                    Log.v("yoyy__________",e.getMessage()+"kooootu");

                    // authzModule.refreshAccess();
                    authzModule.isAuthorized();
                    if (!e.getMessage().matches(OAuthWebViewDialog.OAuthReceiver.DISMISS_ERROR))
                    {
                        //authzModule.refreshAccess();
                        authzModule.deleteAccount();
                    }
                    callback.onFailure(e);

                }
            });

        } catch (Exception e) {
            e.printStackTrace();
            Log.v("yoyy__________",e.getMessage()+"kotu");
            throw new RuntimeException(e);


        }
    }

    public static boolean isConnected()
    {
        return AuthorizationManager.getModule("KeyCloakAuthz").isAuthorized();
    }
}
