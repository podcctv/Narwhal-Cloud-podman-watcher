import React from 'react';
import {
  ConsoleShell,
  type ConsoleShellProps,
  type ConsoleTab,
} from '../../v2/layout/ConsoleShell';

export type Tab = ConsoleTab;
export type AppHeaderProps = ConsoleShellProps;

export const AppHeader: React.FC<AppHeaderProps> = (props) => <ConsoleShell {...props} />;
