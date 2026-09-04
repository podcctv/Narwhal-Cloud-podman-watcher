import React, { useEffect, useRef } from 'react';
import * as echarts from 'echarts';
import { HistoryPoint } from '../../api/types';

interface ResourceChartProps {
  history: HistoryPoint[];
}

export const ResourceChart: React.FC<ResourceChartProps> = ({ history }) => {
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstance = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!chartRef.current) return;

    if (!chartInstance.current) {
      chartInstance.current = echarts.init(chartRef.current, 'dark');
    }

    const timestamps = history.map((h) => h.timestamp_iso_utc8?.split(' ')[1] || '');
    const cpuSeries = history.map((h) => Number((h.cpu_percent || 0).toFixed(2)));
    const memSeries = history.map((h) => Number((h.mem_percent || 0).toFixed(2)));

    const option: echarts.EChartsOption = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'axis',
        backgroundColor: 'rgba(15, 23, 42, 0.95)',
        borderColor: '#334155',
        textStyle: { color: '#f8fafc', fontSize: 12, fontFamily: 'Fira Sans' },
        formatter: (params: any) => {
          if (!Array.isArray(params) || params.length === 0) return '';
          const time = params[0].name;
          let html = `<div class="font-mono font-bold text-xs mb-1 text-slate-300">${time}</div>`;
          params.forEach((p: any) => {
            html += `<div class="flex items-center justify-between gap-4 text-xs">
              <span style="color:${p.color}">● ${p.seriesName}</span>
              <span class="font-mono font-bold">${p.value}%</span>
            </div>`;
          });
          return html;
        },
      },
      legend: {
        data: ['CPU %', '内存 %'],
        textStyle: { color: '#94a3b8', fontSize: 11 },
        top: 0,
        right: 10,
      },
      grid: {
        top: 30,
        left: 35,
        right: 15,
        bottom: 25,
      },
      xAxis: {
        type: 'category',
        data: timestamps,
        boundaryGap: false,
        axisLine: { lineStyle: { color: '#334155' } },
        axisLabel: { color: '#64748b', fontSize: 10, fontFamily: 'Fira Code' },
      },
      yAxis: {
        type: 'value',
        max: 100,
        splitLine: { lineStyle: { color: '#1e293b' } },
        axisLabel: {
          color: '#64748b',
          fontSize: 10,
          fontFamily: 'Fira Code',
          formatter: '{value}%',
        },
      },
      series: [
        {
          name: 'CPU %',
          type: 'line',
          smooth: true,
          showSymbol: false,
          data: cpuSeries,
          itemStyle: { color: '#38bdf8' },
          lineStyle: { width: 2 },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(56, 189, 248, 0.25)' },
              { offset: 1, color: 'rgba(56, 189, 248, 0.0)' },
            ]),
          },
        },
        {
          name: '内存 %',
          type: 'line',
          smooth: true,
          showSymbol: false,
          data: memSeries,
          itemStyle: { color: '#22c55e' },
          lineStyle: { width: 2 },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(34, 197, 94, 0.25)' },
              { offset: 1, color: 'rgba(34, 197, 94, 0.0)' },
            ]),
          },
        },
      ],
    };

    chartInstance.current.setOption(option);

    const handleResize = () => chartInstance.current?.resize();
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
    };
  }, [history]);

  return <div ref={chartRef} className="h-56 w-full" />;
};
