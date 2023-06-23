package com.hfad.catchat;

import android.os.Bundle;

import androidx.preference.PreferenceFragmentCompat;

public class OrganizationSettingsFragment extends PreferenceFragmentCompat {

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.organization_preferences, rootKey);
    }
}