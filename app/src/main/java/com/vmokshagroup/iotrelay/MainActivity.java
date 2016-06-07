package com.vmokshagroup.iotrelay;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import com.amazonaws.auth.CognitoCachingCredentialsProvider;
import com.amazonaws.mobileconnectors.iot.AWSIotKeystoreHelper;
import com.amazonaws.mobileconnectors.iot.AWSIotMqttClientStatusCallback;
import com.amazonaws.mobileconnectors.iot.AWSIotMqttLastWillAndTestament;
import com.amazonaws.mobileconnectors.iot.AWSIotMqttManager;
import com.amazonaws.mobileconnectors.iot.AWSIotMqttNewMessageCallback;
import com.amazonaws.mobileconnectors.iot.AWSIotMqttQos;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.iot.AWSIotClient;
import com.amazonaws.services.iot.model.AttachPrincipalPolicyRequest;
import com.amazonaws.services.iot.model.CreateKeysAndCertificateRequest;
import com.amazonaws.services.iot.model.CreateKeysAndCertificateResult;

import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.util.UUID;

public class MainActivity extends AppCompatActivity {
    static final String LOG_TAG = MainActivity.class.getCanonicalName();

    // --- Constants to modify per your configuration ---

    // IoT endpoint
    // Replace XXXXXXXXXX.iot.<region>.amazonaws.com with your AWS IOT Things REST API endpoint https://XXXXXXXXXX.iot.<region>.amazonaws.com/things/YourThings/shadow
    private static final String CUSTOMER_SPECIFIC_ENDPOINT = "XXXXXXXXXX.iot.<region>.amazonaws.com";
    // Cognito pool ID. For this app, pool needs to be unauthenticated pool with

   /* CognitoCachingCredentialsProvider credentialsProvider = new CognitoCachingCredentialsProvider(
             getApplicationContext(),
             "us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", // YOUR COGNITO POOL ID
             Regions.US_EAST_1 // Region
     );*/


    private static final String COGNITO_POOL_ID = "us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
    // Name of the AWS IoT policy to attach to a newly created certificate
    private static final String AWS_IOT_POLICY_NAME = "YOUR THING POLICY NAME";

    // Region of AWS IoT
    private static final Regions MY_REGION = Regions.US_EAST_1;
    // Filename of KeyStore file on the filesystem
    private static final String KEYSTORE_NAME = "iot_keystore";
    // Password for the private key in the KeyStore
    private static final String KEYSTORE_PASSWORD = "password";
    // Certificate and key aliases in the KeyStore
    private static final String CERTIFICATE_ID = "default";

    private String strTopic = "YOUR TOPIC"; //example: $aws/things/YOURTHING/shadow/update
    private String strTopicGet = "$aws/things/RelayControlThing/shadow/get/accepted";
    private String strMessage1 = "{\"state\": {\"desired\": {\"ledBarStatus\":";
    private String strMessage2 = "}}}";
    private TextView tvConnectionStatus;
    private TextView tvDevioceStatus;
    private Switch aSwitch;
    private Button mBntStatus;

    AWSIotClient mIotAndroidClient;
    AWSIotMqttManager mqttManager;
    String clientId;
    String keystorePath;
    String keystoreName;
    String keystorePassword;

    KeyStore clientKeyStore = null;
    String certificateId;

    CognitoCachingCredentialsProvider credentialsProvider;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);


        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        tvConnectionStatus = (TextView) findViewById(R.id.text_status);
        tvDevioceStatus = (TextView) findViewById(R.id.text_device_status);
        aSwitch = (Switch) findViewById(R.id.switch_);
        aSwitch.setEnabled(false);
        mBntStatus = (Button) findViewById(R.id.get_status);
        mBntStatus.setEnabled(false);
        clientId = UUID.randomUUID().toString();


        // Initialize the AWS Cognito credentials provider
        credentialsProvider = new CognitoCachingCredentialsProvider(
                getApplicationContext(), // context
                COGNITO_POOL_ID, // Identity Pool ID
                MY_REGION // Region
        );

        Region region = Region.getRegion(MY_REGION);

        // MQTT Client
        mqttManager = new AWSIotMqttManager(clientId, CUSTOMER_SPECIFIC_ENDPOINT);

        // Set keepalive to 10 seconds.  Will recognize disconnects more quickly but will also send
        // MQTT pings every 10 seconds.
        mqttManager.setKeepAlive(10);

        // Set Last Will and Testament for MQTT.  On an unclean disconnect (loss of connection)
        // AWS IoT will publish this message to alert other clients.
        AWSIotMqttLastWillAndTestament lwt = new AWSIotMqttLastWillAndTestament("my/lwt/topic",
                "Android client lost connection", AWSIotMqttQos.QOS0);
        mqttManager.setMqttLastWillAndTestament(lwt);

        // IoT Client (for creation of certificate if needed)
        mIotAndroidClient = new AWSIotClient(credentialsProvider);
        mIotAndroidClient.setRegion(region);

        keystorePath = getFilesDir().getPath();
        keystoreName = KEYSTORE_NAME;
        keystorePassword = KEYSTORE_PASSWORD;
        certificateId = CERTIFICATE_ID;

        // To load cert/key from keystore on filesystem
        try {
            if (AWSIotKeystoreHelper.isKeystorePresent(keystorePath, keystoreName)) {
                if (AWSIotKeystoreHelper.keystoreContainsAlias(certificateId, keystorePath,
                        keystoreName, keystorePassword)) {
                    Log.i(LOG_TAG, "Certificate " + certificateId
                            + " found in keystore - using for MQTT.");
                    // load keystore from file into memory to pass on connection
                    clientKeyStore = AWSIotKeystoreHelper.getIotKeystore(certificateId,
                            keystorePath, keystoreName, keystorePassword);
                    try {
                        mqttManager.connect(clientKeyStore, new AWSIotMqttClientStatusCallback() {
                            @Override
                            public void onStatusChanged(final AWSIotMqttClientStatus status,
                                                        final Throwable throwable) {
                                Log.d(LOG_TAG, "Status = " + String.valueOf(status));

                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        if (status == AWSIotMqttClientStatus.Connecting) {
                                            tvConnectionStatus.setText("Connecting...");
                                            mBntStatus.setEnabled(false);
                                            aSwitch.setEnabled(false);

                                        } else if (status == AWSIotMqttClientStatus.Connected) {
                                            tvConnectionStatus.setText("Connected");
                                            mBntStatus.setEnabled(true);
                                            aSwitch.setEnabled(true);

                                        } else if (status == AWSIotMqttClientStatus.Reconnecting) {
                                            if (throwable != null) {
                                                Log.e(LOG_TAG, "Connection error.", throwable);
                                            }
                                            tvConnectionStatus.setText("Reconnecting");
                                            mBntStatus.setEnabled(false);
                                            aSwitch.setEnabled(true);
                                        } else if (status == AWSIotMqttClientStatus.ConnectionLost) {
                                            if (throwable != null) {
                                                Log.e(LOG_TAG, "Connection error.", throwable);
                                            }
                                            tvConnectionStatus.setText("Disconnected");
                                            mBntStatus.setEnabled(false);
                                            aSwitch.setEnabled(false);
                                        } else {
                                            tvConnectionStatus.setText("Disconnected");
                                            mBntStatus.setEnabled(false);
                                            aSwitch.setEnabled(false);

                                        }
                                    }
                                });
                            }
                        });
                    } catch (final Exception e) {
                        Log.e(LOG_TAG, "Connection error.", e);
                        tvConnectionStatus.setText("Error! " + e.getMessage());
                    }


                } else {
                    Log.i(LOG_TAG, "Key/cert " + certificateId + " not found in keystore.");
                }
            } else {
                Log.i(LOG_TAG, "Keystore " + keystorePath + "/" + keystoreName + " not found.");
            }
        } catch (Exception e) {
            Log.e(LOG_TAG, "An error occurred retrieving cert/key from keystore.", e);
        }

        if (clientKeyStore == null) {
            Log.i(LOG_TAG, "Cert/key was not found in keystore - creating new key and certificate.");

            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        // Create a new private key and certificate. This call
                        // creates both on the server and returns them to the
                        // device.
                        CreateKeysAndCertificateRequest createKeysAndCertificateRequest =
                                new CreateKeysAndCertificateRequest();
                        createKeysAndCertificateRequest.setSetAsActive(true);
                        final CreateKeysAndCertificateResult createKeysAndCertificateResult;
                        createKeysAndCertificateResult =
                                mIotAndroidClient.createKeysAndCertificate(createKeysAndCertificateRequest);
                        Log.i(LOG_TAG,
                                "Cert ID: " +
                                        createKeysAndCertificateResult.getCertificateId() +
                                        " created.");

                        // store in keystore for use in MQTT client
                        // saved as alias "default" so a new certificate isn't
                        // generated each run of this application
                        AWSIotKeystoreHelper.saveCertificateAndPrivateKey(certificateId,
                                createKeysAndCertificateResult.getCertificatePem(),
                                createKeysAndCertificateResult.getKeyPair().getPrivateKey(),
                                keystorePath, keystoreName, keystorePassword);

                        // load keystore from file into memory to pass on
                        // connection
                        clientKeyStore = AWSIotKeystoreHelper.getIotKeystore(certificateId,
                                keystorePath, keystoreName, keystorePassword);

                        // Attach a policy to the newly created certificate.
                        // This flow assumes the policy was already created in
                        // AWS IoT and we are now just attaching it to the
                        // certificate.
                        AttachPrincipalPolicyRequest policyAttachRequest =
                                new AttachPrincipalPolicyRequest();
                        policyAttachRequest.setPolicyName(AWS_IOT_POLICY_NAME);
                        policyAttachRequest.setPrincipal(createKeysAndCertificateResult
                                .getCertificateArn());
                        mIotAndroidClient.attachPrincipalPolicy(policyAttachRequest);

                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                try {
                                    mqttManager.connect(clientKeyStore, new AWSIotMqttClientStatusCallback() {
                                        @Override
                                        public void onStatusChanged(final AWSIotMqttClientStatus status,
                                                                    final Throwable throwable) {
                                            Log.d(LOG_TAG, "Status = " + String.valueOf(status));

                                            runOnUiThread(new Runnable() {
                                                @Override
                                                public void run() {
                                                    if (status == AWSIotMqttClientStatus.Connecting) {
                                                        tvConnectionStatus.setText("Connecting...");
                                                        mBntStatus.setEnabled(false);
                                                        aSwitch.setEnabled(false);

                                                    } else if (status == AWSIotMqttClientStatus.Connected) {
                                                        tvConnectionStatus.setText("Connected");
                                                        mBntStatus.setEnabled(true);
                                                        aSwitch.setEnabled(true);
                                                    } else if (status == AWSIotMqttClientStatus.Reconnecting) {
                                                        if (throwable != null) {
                                                            Log.e(LOG_TAG, "Connection error.", throwable);
                                                        }
                                                        tvConnectionStatus.setText("Reconnecting");
                                                        mBntStatus.setEnabled(false);
                                                        aSwitch.setEnabled(false);
                                                    } else if (status == AWSIotMqttClientStatus.ConnectionLost) {
                                                        if (throwable != null) {
                                                            Log.e(LOG_TAG, "Connection error.", throwable);
                                                        }
                                                        tvConnectionStatus.setText("Disconnected");
                                                        mBntStatus.setEnabled(false);
                                                        aSwitch.setEnabled(false);
                                                    } else {
                                                        tvConnectionStatus.setText("Disconnected");
                                                        mBntStatus.setEnabled(false);
                                                        aSwitch.setEnabled(false);

                                                    }
                                                }
                                            });
                                        }
                                    });
                                } catch (final Exception e) {
                                    Log.e(LOG_TAG, "Connection error.", e);
                                    tvConnectionStatus.setText("Error! " + e.getMessage());
                                }
                            }
                        });
                    } catch (Exception e) {
                        Log.e(LOG_TAG,
                                "Exception occurred when generating new private key and certificate.",
                                e);
                    }


                }
            }).start();
        }

        mBntStatus.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                final String topic = strTopicGet;

                Log.d(LOG_TAG, "topic = " + topic);


                try {
                    mqttManager.subscribeToTopic(topic, AWSIotMqttQos.QOS1,
                            new AWSIotMqttNewMessageCallback() {
                                @Override
                                public void onMessageArrived(final String topic, final byte[] data) {
                                    runOnUiThread(new Runnable() {
                                        @Override
                                        public void run() {
                                            try {
                                                String message = new String(data, "UTF-8");
                                                Log.d(LOG_TAG, "Message arrived:");
                                                Log.d(LOG_TAG, "   Topic: " + topic);
                                                Log.d(LOG_TAG, " Message: " + message);
                                                Toast.makeText(getApplicationContext(),message,Toast.LENGTH_SHORT).show();
//                                                try {
//                                                    JSONObject object = new JSONObject(message);
//                                                    JSONObject statusObj = object.getJSONObject("state");
//                                                    JSONObject reported = statusObj.getJSONObject("reported");

//                                                    String strDeviceStatus = reported.getString("ledBarStatus");
//                                                    if(strDeviceStatus != null && Integer.parseInt(strDeviceStatus) == 1){
//                                                        aSwitch.setChecked(true);
//                                                    }else if(strDeviceStatus != null && Integer.parseInt(strDeviceStatus) != 1){
//                                                        aSwitch.setChecked(false);
//                                                    }

//                                                } catch (JSONException e) {
//                                                    e.printStackTrace();
//                                                }

                                            } catch (UnsupportedEncodingException e) {
                                                Log.e(LOG_TAG, "Message encoding error.", e);
                                            }
                                        }
                                    });
                                }
                            });
                } catch (Exception e) {
                    Log.e(LOG_TAG, "Subscription error.", e);
                }
            }
        });

        aSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    final String msg =  strMessage1+1+strMessage2;

                    try {
                        mqttManager.publishString(msg, strTopic, AWSIotMqttQos.QOS1);
                    } catch (Exception e) {
                        Log.e(LOG_TAG, "Publish error.", e);
                    }
                } else {
                    final String msg =  strMessage1+0+strMessage2;

                    try {
                        mqttManager.publishString(msg, strTopic, AWSIotMqttQos.QOS1);
                    } catch (Exception e) {
                        Log.e(LOG_TAG, "Publish error.", e);
                    }
                }
            }
        });
    }
}
