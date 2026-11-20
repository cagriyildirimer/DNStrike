export interface SparkSeries {
  label: string;
  color: string;
  values: number[];
}

interface SparklineProps {
  series: SparkSeries[];
  height?: number;
}

// Sparkline renders one or more time-series as thin inline-SVG lines sharing a
// single value axis (never a dual axis). It uses a non-scaling stroke so the 2px
// line stays crisp while the SVG stretches to the card width. It lives inside the
// always-dark live console, so colors are passed in by the caller to match.
export function Sparkline({ series, height = 48 }: SparklineProps) {
  const W = 240;
  const H = height;
  const padY = 4;

  const all = series.flatMap(s => s.values).filter(v => Number.isFinite(v));
  const min = all.length ? Math.min(...all) : 0;
  const max = all.length ? Math.max(...all) : 1;
  const span = max - min || 1;

  const xAt = (i: number, n: number) => (n <= 1 ? W : (i / (n - 1)) * W);
  const yAt = (v: number) => H - padY - ((v - min) / span) * (H - padY * 2);

  return (
    <svg
      className="spark-svg"
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      role="img"
      aria-label={series.map(s => s.label).join(', ')}
      style={{ width: '100%', height }}
    >
      {series.map(s => {
        const n = s.values.length;
        if (n === 0) return null;
        if (n === 1) {
          const y = yAt(s.values[0]);
          return (
            <line
              key={s.label}
              x1={0}
              y1={y}
              x2={W}
              y2={y}
              stroke={s.color}
              strokeWidth={2}
              vectorEffect="non-scaling-stroke"
            />
          );
        }
        const line = s.values.map((v, i) => `${xAt(i, n).toFixed(1)},${yAt(v).toFixed(1)}`).join(' ');
        const area = `0,${H} ${line} ${W},${H}`;
        return (
          <g key={s.label}>
            <polyline points={area} fill={s.color} opacity={0.08} stroke="none" />
            <polyline
              points={line}
              fill="none"
              stroke={s.color}
              strokeWidth={2}
              strokeLinejoin="round"
              strokeLinecap="round"
              vectorEffect="non-scaling-stroke"
            />
          </g>
        );
      })}
    </svg>
  );
}
