import React, { useEffect, useRef } from 'react';
import * as echarts from 'echarts';
import { HistoryPoint } from '../../api/types';
import { fmtMbps } from '../../api/client';

interface NetworkChartProps {
  history: HistoryPoint[];
}

export const NetworkChart: React.FC<NetworkChartProps> = ({ history }) => {
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstance = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!chartRef.current) return;

    if (!chartInstance.current) {
      chartInstance.current = echarts.init(chartRef.current, 'dark');
    }

    const timestamps = history.map((h) => h.timestamp_iso_utc8?.split(' ')[1] || '');
    const rxSeries = history.map((h) => Number(fmtMbps(h.net_rx_bps)));
    const txSeries = history.map((h) => Number(fmtMbps(h.net_tx_bps)));

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
              <span class="font-mono font-bold">${p.value} Mbps</span>
            </div>`;
          });
          return html;
        },
      },
      legend: {
        data: ['下行 RX', '上行 TX'],
        textStyle: { color: '#94a3b8', fontSize: 11 },
        top: 0,
        right: 10,
      },
      grid: {
        top: 30,
        left: 45,
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
        splitLine: { lineStyle: { color: '#1e293b' } },
        axisLabel: {
          color: '#64748b',
          fontSize: 10,
          fontFamily: 'Fira Code',
          formatter: '{value} M',
        },
      },
      series: [
        {
          name: '下行 RX',
          type: 'line',
          smooth: true,
          showSymbol: false,
          data: rxSeries,
          itemStyle: { color: '#2ecc71' },
          lineStyle: { width: 2 },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(46, 204, 113, 0.25)' },
              { offset: 1, color: 'rgba(46, 204, 113, 0.0)' },
            ]),
          },
        },
        {
          name: '上行 TX',
          type: 'line',
          smooth: true,
          showSymbol: false,
          data: txSeries,
          itemStyle: { color: '#f39c12' },
          lineStyle: { width: 2 },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(243, 156, 18, 0.25)' },
              { offset: 1, color: 'rgba(243, 156, 18, 0.0)' },
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
