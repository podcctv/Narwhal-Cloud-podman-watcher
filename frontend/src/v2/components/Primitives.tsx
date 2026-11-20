import React from 'react';
import { Inbox } from 'lucide-react';

export interface EyebrowProps {
  children: React.ReactNode;
  tone?: 'blue' | 'cyan' | 'orange' | 'teal' | 'muted';
  dot?: boolean;
  className?: string;
}

const eyebrowToneClasses: Record<NonNullable<EyebrowProps['tone']>, string> = {
  blue: 'text-[#087bff]',
  cyan: 'text-[#54c7ff]',
  orange: 'text-[#ff6b00]',
  teal: 'text-[#147468]',
  muted: 'text-[#697b9c]',
};

const eyebrowDotClasses: Record<NonNullable<EyebrowProps['tone']>, string> = {
  blue: 'bg-[#087bff]',
  cyan: 'bg-[#00b6ec]',
  orange: 'bg-[#ff6b00]',
  teal: 'bg-[#147468]',
  muted: 'bg-[#697b9c]',
};

/** Tracked monospace uppercase label for RackNerd 2.0 spec headers and sections. */
export const Eyebrow: React.FC<EyebrowProps> = ({
  children,
  tone,
  dot = false,
  className = '',
}) => {
  const toneClass = tone ? eyebrowToneClasses[tone] : '';
  const dotClass = tone ? eyebrowDotClasses[tone] : 'bg-[#00b6ec]';

  return (
    <span className={`rn2-eyebrow inline-flex items-center gap-1.5 ${toneClass} ${className}`.trim()}>
      {dot && <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${dotClass}`} aria-hidden="true" />}
      <span>{children}</span>
    </span>
  );
};

export type StatusPillTone = 'teal' | 'blue' | 'orange' | 'amber' | 'crimson' | 'slate';

export interface StatusPillProps {
  children: React.ReactNode;
  tone?: StatusPillTone;
  size?: 'sm' | 'md';
  icon?: React.ReactNode;
  pulse?: boolean;
  className?: string;
}

const pillToneClass: Record<StatusPillTone, string> = {
  teal: 'rn2-pill-teal',
  blue: 'rn2-pill-blue',
  orange: 'rn2-pill-orange',
  amber: 'rn2-pill-amber',
  crimson: 'rn2-pill-crimson',
  slate: 'rn2-pill-slate',
};

const pillPulseDotClass: Record<StatusPillTone, string> = {
  teal: 'bg-[#147468]',
  blue: 'bg-[#087bff]',
  orange: 'bg-[#ff6b00]',
  amber: 'bg-[#d97706]',
  crimson: 'bg-[#dc2626]',
  slate: 'bg-[#697b9c]',
};

/** High-contrast Light-Ice status pill pairing explicit text labels with semantic tint. */
export const StatusPill: React.FC<StatusPillProps> = ({
  children,
  tone = 'slate',
  size = 'md',
  icon,
  pulse = false,
  className = '',
}) => (
  <span
    className={`rn2-pill ${size === 'sm' ? 'rn2-pill-sm' : ''} ${pillToneClass[tone]} ${className}`.trim()}
  >
    {pulse ? (
      <span className="relative flex h-2 w-2 shrink-0" aria-hidden="true">
        <span className={`animate-ping-slow absolute inline-flex h-full w-full rounded-full opacity-75 ${pillPulseDotClass[tone]}`} />
        <span className={`relative inline-flex h-2 w-2 rounded-full ${pillPulseDotClass[tone]}`} />
      </span>
    ) : (
      icon && <span className="inline-flex shrink-0 items-center" aria-hidden="true">{icon}</span>
    )}
    <span>{children}</span>
  </span>
);

export interface SpecCardProps {
  children: React.ReactNode;
  title?: React.ReactNode;
  eyebrow?: React.ReactNode;
  subtitle?: React.ReactNode;
  badge?: React.ReactNode;
  actions?: React.ReactNode;
  headTone?: 'midnight' | 'blue';
  featured?: boolean;
  as?: 'section' | 'article' | 'div';
  id?: string;
  role?: React.AriaRole;
  className?: string;
  headClassName?: string;
  bodyClassName?: string;
  'aria-labelledby'?: string;
  'aria-label'?: string;
}

/**
 * Dual-contrast RackNerd 2.0 specification card: crisp white body + midnight navy
 * or electric blue header strip. When `bodyClassName` is omitted, children render
 * directly so a `SpecStrip` can sit flush under the header.
 */
export const SpecCard: React.FC<SpecCardProps> = ({
  children,
  title,
  eyebrow,
  subtitle,
  badge,
  actions,
  headTone = 'midnight',
  featured = false,
  as: Tag = 'section',
  id,
  role,
  className = '',
  headClassName = '',
  bodyClassName,
  'aria-labelledby': ariaLabelledBy,
  'aria-label': ariaLabel,
}) => {
  const hasHeader = Boolean(title || eyebrow || subtitle || badge || actions);

  return (
    <Tag
      id={id}
      role={role}
      aria-labelledby={ariaLabelledBy}
      aria-label={ariaLabel}
      className={`rn2-card ${featured ? 'rn2-card-featured' : ''} ${className}`.trim()}
    >
      {hasHeader && (
        <div
          className={`rn2-card-head ${headTone === 'blue' ? 'rn2-card-head-blue' : ''} ${headClassName}`.trim()}
        >
          <div className="min-w-0 flex-1">
            {eyebrow && (
              <span className="rn2-eyebrow block text-[#54c7ff]">{eyebrow}</span>
            )}
            {title && (
              <div className="mt-0.5 flex flex-wrap items-center gap-2 text-sm font-bold leading-snug text-white sm:text-base">
                {title}
              </div>
            )}
            {subtitle && (
              <p className="mt-1 text-xs leading-relaxed text-[#b9d3ee]">{subtitle}</p>
            )}
          </div>
          {(badge || actions) && (
            <div className="flex shrink-0 flex-wrap items-center gap-2">
              {badge}
              {actions}
            </div>
          )}
        </div>
      )}
      {bodyClassName ? <div className={bodyClassName}>{children}</div> : children}
    </Tag>
  );
};

export interface SpecItem {
  label: React.ReactNode;
  value: React.ReactNode;
  hint?: React.ReactNode;
  tone?: 'default' | 'blue' | 'teal' | 'orange' | 'amber' | 'crimson';
  mono?: boolean;
}

export interface SpecStripProps {
  items?: SpecItem[];
  children?: React.ReactNode;
  columnsClassName?: string;
  className?: string;
  ariaLabel?: string;
}

const specValueTone: Record<NonNullable<SpecItem['tone']>, string> = {
  default: 'text-[#0b1636]',
  blue: 'text-[#087bff]',
  teal: 'text-[#147468]',
  orange: 'text-[#ff6b00]',
  amber: 'text-[#9a5b00]',
  crimson: 'text-[#b41835]',
};

/** Recessed Light-Ice spec grid (`#f4f8fd`) with hairline vertical dividers. */
export const SpecStrip: React.FC<SpecStripProps> = ({
  items,
  children,
  columnsClassName = '',
  className = '',
  ariaLabel,
}) => (
  <div
    aria-label={ariaLabel}
    className={`rn2-spec-strip ${columnsClassName} ${className}`.trim()}
  >
    {items
      ? items.map((item, idx) => (
          <div key={idx} className="rn2-spec-cell">
            <div className="truncate text-[11px] font-semibold uppercase tracking-wider text-[#697b9c]">
              {item.label}
            </div>
            <div
              className={`mt-1 wrap-break-word text-base font-bold leading-tight tabular-nums sm:text-lg ${
                item.mono !== false ? 'font-mono' : ''
              } ${specValueTone[item.tone || 'default']}`}
            >
              {item.value}
            </div>
            {item.hint && (
              <div className="mt-1 wrap-break-word text-xs leading-snug text-[#697b9c]">
                {item.hint}
              </div>
            )}
          </div>
        ))
      : children}
  </div>
);

export interface EmptyWellProps {
  title: React.ReactNode;
  description?: React.ReactNode;
  icon?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}

/** Crisp Light-Ice empty-state container with balanced contrast and action slot. */
export const EmptyWell: React.FC<EmptyWellProps> = ({
  title,
  description,
  icon,
  action,
  className = '',
}) => (
  <div
    className={`flex flex-col items-center justify-center rounded-xl border border-dashed border-[#cedae7] bg-[#f4f8fd] px-5 py-8 text-center ${className}`.trim()}
  >
    <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-xl border border-[#cedae7] bg-white text-[#087bff] shadow-xs">
      {icon ?? <Inbox className="h-5 w-5" aria-hidden="true" />}
    </div>
    <p className="text-sm font-bold text-[#0b1636]">{title}</p>
    {description && (
      <p className="mt-1.5 max-w-md wrap-break-word text-xs leading-relaxed text-[#697b9c]">
        {description}
      </p>
    )}
    {action && <div className="mt-4 flex flex-wrap justify-center gap-2">{action}</div>}
  </div>
);

export interface SectionTitleProps {
  title: React.ReactNode;
  eyebrow?: React.ReactNode;
  description?: React.ReactNode;
  icon?: React.ReactNode;
  actions?: React.ReactNode;
  as?: 'h1' | 'h2' | 'h3';
  id?: string;
  className?: string;
}

/** Standardized page/section header for Light-Ice workspaces. */
export const SectionTitle: React.FC<SectionTitleProps> = ({
  title,
  eyebrow,
  description,
  icon,
  actions,
  as: HeadingTag = 'h2',
  id,
  className = '',
}) => (
  <div
    className={`flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between ${className}`.trim()}
  >
    <div className="flex min-w-0 items-start gap-3">
      {icon && (
        <div className="mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#b9d7ff] bg-[#e8f3ff] text-[#087bff]">
          {icon}
        </div>
      )}
      <div className="min-w-0">
        {eyebrow && <Eyebrow tone="blue" className="block">{eyebrow}</Eyebrow>}
        <HeadingTag
          id={id}
          className="mt-0.5 text-lg font-extrabold tracking-tight text-[#0b1636] sm:text-xl"
        >
          {title}
        </HeadingTag>
        {description && (
          <p className="mt-1 wrap-break-word text-xs leading-relaxed text-[#697b9c] sm:text-sm">
            {description}
          </p>
        )}
      </div>
    </div>
    {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
  </div>
);
