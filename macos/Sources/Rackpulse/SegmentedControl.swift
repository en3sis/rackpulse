import SwiftUI

struct SegmentedControl<Value: Hashable>: View {
    @Binding var selection: Value
    let options: [(Value, String)]
    var icon: (Value) -> String? = { _ in nil }

    @Namespace private var namespace
    @State private var pill: Value?

    var body: some View {
        HStack(spacing: 2) {
            ForEach(options, id: \.0) { value, title in
                let selected = value == (pill ?? selection)
                Button {
                    withAnimation(.snappy(duration: 0.22)) { pill = value }
                    var transaction = Transaction(animation: nil)
                    transaction.disablesAnimations = true
                    withTransaction(transaction) { selection = value }
                } label: {
                    HStack(spacing: 4) {
                        if let symbol = icon(value) {
                            Image(systemName: symbol)
                                .font(.system(size: 11, weight: .medium))
                        }
                        Text(title)
                            .lineLimit(1)
                    }
                        .font(.system(size: 12.5, weight: selected ? .semibold : .medium))
                        .foregroundStyle(selected ? Theme.text : Theme.secondary)
                        .frame(maxWidth: .infinity, minHeight: 24)
                        .background {
                            if selected {
                                RoundedRectangle(cornerRadius: 6)
                                    .fill(Theme.selectedTab)
                                    .shadow(color: .black.opacity(0.14), radius: 1.5, y: 1)
                                    .matchedGeometryEffect(id: "selection", in: namespace)
                            }
                        }
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(selected ? .isSelected : [])
            }
        }
        .padding(2)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 8))
        .onChange(of: selection) { pill = selection }
    }
}
