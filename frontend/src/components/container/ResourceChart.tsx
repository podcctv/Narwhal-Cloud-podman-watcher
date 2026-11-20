import React, { useEffect, useRef } from 'react';
import * as echarts from 'echarts/core';
import { LineChart } from 'echarts/charts';
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import { HistoryPoint } from '../../api/types';

echarts.use([LineChart, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer]);

interface ResourceChartProps {
  history: HistoryPoint[];
}

export const ResourceChart: React.FC<ResourceChartProps> = ({ history }) => {
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstance = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!chartRef.current) return;

    if (!chartInstance.current) {
      chartInstance.current = echarts.init(chartRef.current);
    }

    const timestamps = history.map((h) => h.timestamp_iso_utc8?.split(' ')[1] || '');
    const cpuSeries = history.map((h) => Number((h.cpu_percent || 0).toFixed(2)));
    const memSeries = history.map((h) => Number((h.mem_percent || 0).toFixed(2)));

    const option: echarts.EChartsCoreOption = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'axis',
        backgroundColor: '#ffffff',
        borderColor: '#cedae7',
        borderWidth: 1,
        textStyle: {
          color: '#0b1636',
          fontSize: 12,
          fontFamily: "'Plus Jakarta Sans', 'Segoe UI', sans-serif",
        },
        extraCssText: 'box-shadow: 0 8px 24px -10px rgba(7, 51, 101, 0.22); border-radius: 10px;',
        formatter: (params: any) => {
          if (!Array.isArray(params) || params.length === 0) return '';
          const time = params[0].name;
          let html = `<div style="font-family:Inconsolata,'Fira Code',monospace;font-weight:700;font-size:12px;margin-bottom:4px;color:#31485e">${time}</div>`;
          params.forEach((p: any) => {
            html += `<div style="display:flex;align-items:center;justify-content:space-between;gap:16px;font-size:12px;color:#0b1636">
              <span style="color:${p.color};font-weight:600">● ${p.seriesName}</span>
              <span style="font-family:Inconsolata,'Fira Code',monospace;font-weight:700;color:#0b1636">${p.value}%</span>
            </div>`;
          });
          return html;
        },
      },
      legend: {
        data: ['CPU %', '内存 %'],
        textStyle: { color: '#475569', fontSize: 11 },
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
        axisLine: { lineStyle: { color: '#cedae7' } },
        axisLabel: { color: '#475569', fontSize: 10, fontFamily: "Inconsolata, 'Fira Code', monospace" },
      },
      yAxis: {
        type: 'value',
        max: 100,
        splitLine: { lineStyle: { color: '#e1ebf4' } },
        axisLabel: {
          color: '#475569',
          fontSize: 10,
          fontFamily: "Inconsolata, 'Fira Code', monospace",
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
          itemStyle: { color: '#087bff' },
          lineStyle: { width: 2 },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(8, 123, 255, 0.22)' },
              { offset: 1, color: 'rgba(8, 123, 255, 0.0)' },
            ]),
          },
        },
        {
          name: '内存 %',
          type: 'line',
          smooth: true,
          showSymbol: false,
          data: memSeries,
          itemStyle: { color: '#ff6b00' },
          lineStyle: { width: 2 },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(255, 107, 0, 0.20)' },
              { offset: 1, color: 'rgba(255, 107, 0, 0.0)' },
            ]),
          },
        },
      ],
    };

    chartInstance.current.setOption(option);

    const handleResize = () => chartInstance.current?.resize();
    window.addEventListener('resize', handleResize);

    let resizeObserver: ResizeObserver | null = null;
    if (typeof ResizeObserver !== 'undefined' && chartRef.current) {
      resizeObserver = new ResizeObserver(() => {
        chartInstance.current?.resize();
      });
      resizeObserver.observe(chartRef.current);
    }

    return () => {
      window.removeEventListener('resize', handleResize);
      resizeObserver?.disconnect();
    };
  }, [history]);

  // Clean up ECharts instance on unmount to prevent memory leaks
  useEffect(() => {
    return () => {
      chartInstance.current?.dispose();
      chartInstance.current = null;
    };
  }, []);

  return <div ref={chartRef} className="h-56 w-full" />;
};
