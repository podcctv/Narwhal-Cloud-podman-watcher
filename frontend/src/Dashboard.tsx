import React from 'react';
import { DashboardV2, type DashboardV2Props } from './v2/dashboard/DashboardV2';

export type { QuickOpsTarget, WorkspaceFocus } from './v2/dashboard/HeroKpiBar';
export type { DashboardV2Props, DashboardTab } from './v2/dashboard/DashboardV2';

export const Dashboard: React.FC<DashboardV2Props> = (props) => <DashboardV2 {...props} />;
