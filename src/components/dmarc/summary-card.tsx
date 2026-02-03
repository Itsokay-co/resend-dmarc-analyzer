'use client';

interface SummaryCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  variant?: 'default' | 'success' | 'danger' | 'warning';
  subtitleVariant?: 'default' | 'danger';
}

export function SummaryCard({
  title,
  value,
  subtitle,
  variant = 'default',
  subtitleVariant = 'default',
}: SummaryCardProps) {
  const variantStyles = {
    default: 'border-gray-3',
    success: 'border-green/30 bg-green-dim',
    danger: 'border-red/30 bg-red-dim',
    warning: 'border-yellow/30 bg-yellow-dim',
  };

  const valueStyles = {
    default: 'text-gray-10',
    success: 'text-green',
    danger: 'text-red',
    warning: 'text-yellow',
  };

  const subtitleStyles = {
    default: 'text-gray-5',
    danger: 'text-red',
  };

  return (
    <div className={`rounded-xl border p-4 ${variantStyles[variant]}`}>
      <p className="text-sm text-gray-6">{title}</p>
      <p className={`text-2xl font-semibold ${valueStyles[variant]}`}>
        {value}
      </p>
      {subtitle && (
        <p className={`text-xs mt-1 ${subtitleStyles[subtitleVariant]}`}>
          {subtitle}
        </p>
      )}
    </div>
  );
}
