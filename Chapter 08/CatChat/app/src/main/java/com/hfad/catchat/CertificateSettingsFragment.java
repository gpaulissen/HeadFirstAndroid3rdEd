package com.hfad.catchat;

import android.os.Bundle;

import androidx.preference.PreferenceFragmentCompat;

public class CertificateSettingsFragment extends PreferenceFragmentCompat {

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.certificate_preferences, rootKey);
    }
}
