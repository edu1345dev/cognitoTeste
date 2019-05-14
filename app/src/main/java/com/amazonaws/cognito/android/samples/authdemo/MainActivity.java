/*
 * Copyright 2013-2017 Amazon.com, Inc. or its affiliates.
 * All Rights Reserved.
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

package com.amazonaws.cognito.android.samples.authdemo;

import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Handler;
import android.os.HandlerThread;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentTransaction;
import android.os.Bundle;
import android.support.v7.app.AlertDialog;
import android.util.Log;
import android.view.TextureView;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;

import com.amazonaws.cognito.android.samples.authdemo.fragments.AuthUserFragment;
import com.amazonaws.cognito.android.samples.authdemo.fragments.UnauthUserFragment;
import com.amazonaws.mobileconnectors.cognitoauth.Auth;
import com.amazonaws.mobileconnectors.cognitoauth.AuthUserSession;
import com.amazonaws.mobileconnectors.cognitoauth.handlers.AuthHandler;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoDevice;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUser;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserAttributes;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserCodeDeliveryDetails;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserPool;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserSession;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.continuations.AuthenticationContinuation;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.continuations.AuthenticationDetails;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.continuations.ChallengeContinuation;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.continuations.MultiFactorAuthenticationContinuation;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.handlers.AuthenticationHandler;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.handlers.SignUpHandler;
import com.amazonaws.regions.Regions;

public class MainActivity extends FragmentActivity
        implements AuthUserFragment.OnFragmentInteractionListener,
        UnauthUserFragment.OnFragmentInteractionListener {
    private static final String TAG = "CognitoAuthDemo";
    private Auth auth;
    private AlertDialog userDialog;
    private Uri appRedirect;
    private CognitoUserPool userPool;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initCognito();
        setNewUserFragment();
        createUserPoll();
    }

    private void createUserPoll() {
        userPool = new CognitoUserPool(
                this,
                getString(R.string.user_pool_id),
                getString(R.string.cognito_client_id),
                getString(R.string.cognito_client_secret),
                Regions.US_EAST_2
        );
    }

    private void signUpUser() {
        CognitoUserAttributes attr = new CognitoUserAttributes();
        attr.addAttribute("email", "123@123.com");
        attr.addAttribute("given_name", "jose santos");

        SignUpHandler handler = new SignUpHandler() {
            @Override
            public void onSuccess(CognitoUser user, boolean signUpConfirmationState, CognitoUserCodeDeliveryDetails cognitoUserCodeDeliveryDetails) {
                Log.d("handler", user.toString());
            }

            @Override
            public void onFailure(Exception exception) {
                Log.e("handler", exception.getMessage());
            }
        };

        userPool.signUpInBackground("jose.santos", "123456", attr, null, handler);
    }

    private void signInUser() {
        final CognitoUser cognitoUser = userPool.getUser();

        final AuthenticationDetails authDetails =
                new AuthenticationDetails("amanda.ramos", "123456", null);

        Async async = new Async();
        async.execute(cognitoUser, authDetails, new AsyncCallback() {
            @Override
            public void success(CognitoUserSession session) { ;
                TextView textView = findViewById(R.id.textViewTitle);
                textView.setText("Olá "+session.getUsername());
            }
        });
    }

    interface AsyncCallback{
        void success(CognitoUserSession session);
    }

    static class Async extends AsyncTask<Object, Void, Void>{
        private AsyncCallback callback;
        private CognitoUserSession session;

        @Override
        protected Void doInBackground(Object... params) {
            runLogin((CognitoUser) params[0], (AuthenticationDetails) params[1]);
            callback = (AsyncCallback) params[2];
            return null;
        }

        @Override
        protected void onPostExecute(Void aVoid) {
            super.onPostExecute(aVoid);
            callback.success(session);
        }

        private void runLogin(final CognitoUser cognitoUser, AuthenticationDetails authDetails) {
            cognitoUser.initiateUserAuthentication(authDetails, new AuthenticationHandler() {
                @Override
                public void onSuccess(CognitoUserSession userSession, CognitoDevice newDevice) {
                    Log.d("auth", userSession.getAccessToken().toString());
                    session = userSession;
                }

                @Override
                public void getAuthenticationDetails(AuthenticationContinuation authenticationContinuation, String userId) {
                    Log.d("auth", authenticationContinuation.toString());
                }

                @Override
                public void getMFACode(MultiFactorAuthenticationContinuation continuation) {

                }

                @Override
                public void authenticationChallenge(ChallengeContinuation continuation) {

                }

                @Override
                public void onFailure(Exception exception) {
                    Log.e("auth", exception.getLocalizedMessage());
                }
            }, true).run();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        Intent activityIntent = getIntent();
        //  -- Call Auth.getTokens() to get Cognito JWT --
        if (activityIntent.getData() != null &&
                appRedirect.getHost().equals(activityIntent.getData().getHost())) {
            auth.getTokens(activityIntent.getData());
        }
    }

    /**
     * Sets new user fragment on the screen.
     */
    private void setNewUserFragment() {
        UnauthUserFragment newUserFragment = new UnauthUserFragment();
        FragmentTransaction transaction = getSupportFragmentManager().beginTransaction();
        transaction.replace(R.id.frameLayoutContainer, newUserFragment);
        transaction.commit();
        setScreenImages();
    }

    /**
     * Sets auth user fragment.
     *
     * @param session {@link AuthUserSession} containing tokens for a user.
     */
    private void setAuthUserFragment(AuthUserSession session) {
        AuthUserFragment userFragment = new AuthUserFragment();

        Bundle fragArgs = new Bundle();
        fragArgs.putString(getString(R.string.app_access_token), session.getAccessToken().getJWTToken());
        fragArgs.putString(getString(R.string.app_id_token), session.getIdToken().getJWTToken());
        userFragment.setArguments(fragArgs);

        FragmentTransaction transaction = getSupportFragmentManager().beginTransaction();
        transaction.replace(R.id.frameLayoutContainer, userFragment);
        transaction.commit();
        setScreenImages();
    }

    /**
     * Handles button press.
     *
     * @param signIn When {@code True} this performs sign-in.
     */
    public void onButtonPress(boolean signIn) {
//        signUpUser();
        signInUser();

//        Log.d(" -- ", "Button press: " + signIn);
//        if (signIn) {
//            this.auth.getSession();
//        } else {
//            this.auth.signOut();
//        }
    }

    @Override
    public void showPopup(String title, String content) {
        showDialogMessage(title, content);
    }

    /**
     * Setup authentication with Cognito.
     */
    void initCognito() {
        //  -- Create an instance of Auth --
        Auth.Builder builder = new Auth.Builder().setAppClientId(getString(R.string.cognito_client_id))
                .setAppClientSecret(getString(R.string.cognito_client_secret))
                .setAppCognitoWebDomain(getString(R.string.cognito_web_domain))
                .setApplicationContext(getApplicationContext())
                .setAuthHandler(new callback())
                .setSignInRedirect(getString(R.string.app_redirect))
                .setSignOutRedirect(getString(R.string.app_redirect));
        this.auth = builder.build();
        appRedirect = Uri.parse(getString(R.string.app_redirect));
    }

    /**
     * Callback handler for Amazon Cognito.
     */
    class callback implements AuthHandler {

        @Override
        public void onSuccess(AuthUserSession authUserSession) {
            // Show tokens for the authenticated user
            setAuthUserFragment(authUserSession);
        }

        @Override
        public void onSignout() {
            // Back to new user screen.
            setNewUserFragment();
        }

        @Override
        public void onFailure(Exception e) {
            Log.e(TAG, "Failed to auth", e);
        }
    }

    /**
     * Show an popup dialog.
     *
     * @param title
     * @param body
     */
    private void showDialogMessage(String title, String body) {
        final AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(title).setMessage(body).setNeutralButton("OK", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                try {
                    userDialog.dismiss();

                } catch (Exception e) {
                    // Log failure
                    Log.e(TAG, "Dialog failure", e);
                }
            }
        });
        userDialog = builder.create();
        userDialog.show();
    }

    /**
     * Sets images on the screen.
     */
    private void setScreenImages() {
        ImageView cognitoLogo = (ImageView) findViewById(R.id.imageViewCognito);
        cognitoLogo.setImageDrawable(getDrawable(R.drawable.ic_mobileservices_amazoncognito));
    }
}
