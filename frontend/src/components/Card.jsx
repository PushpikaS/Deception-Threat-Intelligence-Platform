function Card({ title, children, className = '', actions }) {
  return (
    <div className={`bg-surface-light border border-surface-border rounded-xl animate-in ${className}`}>
      {title && (
        <div className="px-5 py-4 border-b border-surface-border flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">{title}</h2>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
      )}
      <div className="p-5">{children}</div>
    </div>
  )
}

export default Card