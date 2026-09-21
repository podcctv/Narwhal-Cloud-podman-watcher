import React from 'react';
import { SettingsView } from '../settings/SettingsView';
import { ToastMessage } from '../common/Toast';

export const NotificationSettingsView: React.FC<{
  onToast: (type: ToastMessage['type'], message: string) => void;
}> = ({ onToast }) => {
  return <SettingsView onToast={onToast} />;
};
